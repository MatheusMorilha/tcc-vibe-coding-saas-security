// routes/coupons.js
'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const pool = require('../db');                     // instância de pg.Pool
const { requireAuth, requireRole } = require('../middlewares/auth');

const router = express.Router();

// Limita tentativas para dificultar enumeração/brute-force de códigos.
// A chave é a empresa (vinda do token), não só o IP.
const redeemLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `company:${req.auth.companyId}`,
  message: { error: 'TOO_MANY_ATTEMPTS', message: 'Muitas tentativas. Tente novamente mais tarde.' },
});

const bodySchema = z
  .object({
    code: z
      .string()
      .trim()
      .min(3)
      .max(64)
      .regex(/^[A-Za-z0-9_-]+$/, 'Formato de cupom inválido')
      .transform((v) => v.toUpperCase()),
  })
  .strict(); // rejeita campos extras (ex.: companyId, price, discount)

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// Cálculo monetário em centavos (inteiros) para evitar erros de ponto flutuante
const toCents = (n) => Math.round(Number(n) * 100);
const fromCents = (c) => (c / 100).toFixed(2);

function computeDiscountedPriceCents(basePriceCents, type, value) {
  let discount;
  if (type === 'PERCENT') {
    discount = Math.round((basePriceCents * Number(value)) / 100);
  } else {
    discount = toCents(value);
  }
  return Math.max(basePriceCents - discount, 0);
}

/**
 * POST /api/v1/subscription/coupons/redeem
 * Body: { "code": "PROMO10" }
 *
 * O tenant (companyId) e o usuário NUNCA vêm do body ou da URL:
 * são extraídos exclusivamente do token autenticado.
 */
router.post(
  '/subscription/coupons/redeem',
  requireAuth,
  requireRole('OWNER', 'ADMIN'),   // apenas quem pode gerir cobrança
  redeemLimiter,
  async (req, res, next) => {
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'INVALID_REQUEST',
        message: 'Requisição inválida.',
        details: parsed.error.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
      });
    }

    const { code } = parsed.data;
    const { companyId, userId } = req.auth;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 1) Trava a assinatura da empresa (escopo do tenant).
      //    Serializa resgates concorrentes da mesma empresa.
      const subRes = await client.query(
        `SELECT id, plan_id, base_price, current_price, applied_coupon_id
           FROM subscriptions
          WHERE company_id = $1 AND status = 'ACTIVE'
          FOR UPDATE`,
        [companyId]
      );
      if (subRes.rowCount === 0) {
        throw new HttpError(404, 'NO_ACTIVE_SUBSCRIPTION', 'Nenhuma assinatura ativa encontrada.');
      }
      const sub = subRes.rows[0];

      if (sub.applied_coupon_id) {
        throw new HttpError(409, 'COUPON_ALREADY_APPLIED', 'A assinatura já possui um cupom aplicado.');
      }

      // 2) Incremento atômico do contador, validando tudo na própria query.
      //    Se houver 1 uso restante e duas empresas tentarem juntas, só uma passa.
      const couponRes = await client.query(
        `UPDATE coupons
            SET redemptions_count = redemptions_count + 1
          WHERE code = $1
            AND active = TRUE
            AND valid_from <= now()
            AND (valid_until IS NULL OR valid_until > now())
            AND (max_redemptions IS NULL OR redemptions_count < max_redemptions)
            AND (allowed_plan_ids IS NULL OR $2 = ANY(allowed_plan_ids))
        RETURNING id, discount_type, discount_value, duration_cycles`,
        [code, sub.plan_id]
      );

      if (couponRes.rowCount === 0) {
        // Resposta genérica: não revela se o código existe, expirou, esgotou etc.
        throw new HttpError(422, 'COUPON_NOT_ELIGIBLE', 'Cupom inválido ou indisponível para esta assinatura.');
      }
      const coupon = couponRes.rows[0];

      // 3) Registra o resgate. A UNIQUE (coupon_id, company_id) barra duplicidade.
      try {
        await client.query(
          `INSERT INTO coupon_redemptions (coupon_id, company_id, subscription_id, user_id)
           VALUES ($1, $2, $3, $4)`,
          [coupon.id, companyId, sub.id, userId]
        );
      } catch (err) {
        if (err.code === '23505') {
          throw new HttpError(409, 'COUPON_ALREADY_REDEEMED', 'Esta empresa já resgatou este cupom.');
        }
        throw err;
      }

      // 4) Calcula sempre a partir do preço de tabela (base_price), nunca de valores do cliente.
      const baseCents = toCents(sub.base_price);
      const newCents = computeDiscountedPriceCents(baseCents, coupon.discount_type, coupon.discount_value);

      await client.query(
        `UPDATE subscriptions
            SET current_price = $1,
                applied_coupon_id = $2
          WHERE id = $3 AND company_id = $4`,
        [fromCents(newCents), coupon.id, sub.id, companyId]
      );

      // 5) Trilha de auditoria
      await client.query(
        `INSERT INTO audit_logs (company_id, user_id, action, entity, entity_id, metadata)
         VALUES ($1, $2, 'COUPON_REDEEMED', 'subscription', $3, $4)`,
        [
          companyId,
          userId,
          sub.id,
          JSON.stringify({
            couponId: coupon.id,
            previousPrice: sub.current_price,
            newPrice: fromCents(newCents),
          }),
        ]
      );

      await client.query('COMMIT');

      return res.status(200).json({
        subscriptionId: sub.id,
        couponCode: code,
        discount: {
          type: coupon.discount_type,
          value: coupon.discount_value,
          durationCycles: coupon.duration_cycles, // null = permanente
        },
        basePrice: fromCents(baseCents),
        previousMonthlyPrice: sub.current_price,
        monthlyPrice: fromCents(newCents),
        currency: 'BRL',
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      if (err instanceof HttpError) {
        return res.status(err.status).json({ error: err.code, message: err.message });
      }
      return next(err);
    } finally {
      client.release();
    }
  }
);

module.exports = router;