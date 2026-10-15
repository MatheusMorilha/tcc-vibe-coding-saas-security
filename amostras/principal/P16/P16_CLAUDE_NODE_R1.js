'use strict';

/**
 * POST /api/v1/subscription/coupons/redeem
 *
 * Esquema esperado (PostgreSQL):
 *
 * subscriptions(id, company_id, plan_id, status, currency,
 *               base_price_cents,      -- preço de tabela do plano
 *               price_cents,           -- mensalidade efetiva (com desconto)
 *               coupon_id, discount_cents, discount_ends_at)
 *
 * coupons(id, code_normalized UNIQUE, is_active, starts_at, expires_at,
 *         discount_type,               -- 'percent' | 'fixed'
 *         percent_bp,                  -- basis points (1..10000) se percent
 *         amount_cents, currency,      -- se fixed
 *         duration_months,             -- NULL = permanente
 *         max_redemptions, redeemed_count,
 *         applicable_plan_ids uuid[],  -- NULL = todos os planos
 *         restricted_company_id)       -- NULL = qualquer empresa
 *
 * coupon_redemptions(id, coupon_id, company_id, user_id, subscription_id,
 *                    redeemed_at, UNIQUE (coupon_id, company_id))
 *
 * audit_logs(id, company_id, user_id, action, metadata jsonb, created_at)
 */

const express = require('express');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

const pool = require('../db'); // instância de pg.Pool
const { authenticate, requireRole } = require('../middlewares/auth');

const router = express.Router();

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// Mensagem única para qualquer falha de validade do cupom,
// evitando que um atacante descubra quais códigos existem.
const invalidCoupon = () =>
  new HttpError(422, 'COUPON_INVALID', 'Cupom inválido ou indisponível.');

const bodySchema = z
  .object({
    code: z
      .string()
      .trim()
      .min(3)
      .max(32)
      .regex(/^[A-Za-z0-9_-]+$/),
  })
  .strict();

// Limita tentativas por empresa (contra brute force de códigos).
const redeemLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `company:${req.auth.companyId}`,
  message: { error: { code: 'RATE_LIMITED', message: 'Muitas tentativas. Tente novamente mais tarde.' } },
});

function computeDiscountCents(coupon, basePriceCents) {
  let discount;
  if (coupon.discount_type === 'percent') {
    discount = Math.floor((basePriceCents * coupon.percent_bp) / 10000);
  } else {
    discount = coupon.amount_cents;
  }
  // Nunca negativo e nunca maior que o preço base.
  return Math.min(Math.max(discount, 0), basePriceCents);
}

router.post(
  '/api/v1/subscription/coupons/redeem',
  authenticate,                         // popula req.auth = { userId, companyId, role }
  requireRole('owner', 'admin', 'billing'),
  redeemLimiter,
  async (req, res, next) => {
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Corpo da requisição inválido.' },
      });
    }

    // O tenant vem SEMPRE do token autenticado, nunca do body/params/query.
    const { companyId, userId } = req.auth;
    const code = parsed.data.code.toUpperCase();

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 1) Trava a assinatura da empresa: serializa resgates concorrentes.
      const subRes = await client.query(
        `SELECT id, plan_id, currency, base_price_cents, price_cents, coupon_id
           FROM subscriptions
          WHERE company_id = $1 AND status = 'active'
          FOR UPDATE`,
        [companyId]
      );
      const sub = subRes.rows[0];
      if (!sub) {
        throw new HttpError(404, 'SUBSCRIPTION_NOT_FOUND', 'Nenhuma assinatura ativa encontrada.');
      }
      if (sub.coupon_id) {
        throw new HttpError(409, 'COUPON_ALREADY_APPLIED', 'A assinatura já possui um cupom ativo.');
      }

      // 2) Busca o cupom válido para este plano e esta empresa.
      const couponRes = await client.query(
        `SELECT *
           FROM coupons
          WHERE code_normalized = $1
            AND is_active = TRUE
            AND (starts_at IS NULL OR starts_at <= now())
            AND (expires_at IS NULL OR expires_at > now())
            AND (applicable_plan_ids IS NULL OR $2 = ANY(applicable_plan_ids))
            AND (restricted_company_id IS NULL OR restricted_company_id = $3)`,
        [code, sub.plan_id, companyId]
      );
      const coupon = couponRes.rows[0];
      if (!coupon) throw invalidCoupon();

      // Cupom de valor fixo só vale se a moeda for a mesma da assinatura.
      if (coupon.discount_type === 'fixed' && coupon.currency !== sub.currency) {
        throw invalidCoupon();
      }

      // 3) Garante uso único por empresa (constraint UNIQUE faz o trabalho).
      const redemption = await client.query(
        `INSERT INTO coupon_redemptions (coupon_id, company_id, user_id, subscription_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (coupon_id, company_id) DO NOTHING
         RETURNING id`,
        [coupon.id, companyId, userId, sub.id]
      );
      if (redemption.rowCount === 0) {
        throw new HttpError(409, 'COUPON_ALREADY_USED', 'Este cupom já foi utilizado por sua empresa.');
      }

      // 4) Incremento atômico respeitando o limite global de resgates.
      const counter = await client.query(
        `UPDATE coupons
            SET redeemed_count = redeemed_count + 1
          WHERE id = $1
            AND (max_redemptions IS NULL OR redeemed_count < max_redemptions)
        RETURNING id`,
        [coupon.id]
      );
      if (counter.rowCount === 0) throw invalidCoupon(); // esgotado

      // 5) Calcula o desconto em centavos (inteiros, sem float).
      const discountCents = computeDiscountCents(coupon, sub.base_price_cents);
      const newPriceCents = sub.base_price_cents - discountCents;

      // 6) Aplica à assinatura (filtrando por company_id por defesa em profundidade).
      const updated = await client.query(
        `UPDATE subscriptions
            SET coupon_id        = $1,
                discount_cents   = $2,
                price_cents      = $3,
                discount_ends_at = CASE
                  WHEN $4::int IS NULL THEN NULL
                  ELSE now() + make_interval(months => $4::int)
                END,
                updated_at       = now()
          WHERE id = $5 AND company_id = $6
        RETURNING discount_ends_at`,
        [coupon.id, discountCents, newPriceCents, coupon.duration_months, sub.id, companyId]
      );

      // 7) Auditoria.
      await client.query(
        `INSERT INTO audit_logs (company_id, user_id, action, metadata)
         VALUES ($1, $2, 'coupon.redeemed', $3)`,
        [
          companyId,
          userId,
          JSON.stringify({
            couponId: coupon.id,
            subscriptionId: sub.id,
            previousPriceCents: sub.price_cents,
            newPriceCents,
          }),
        ]
      );

      await client.query('COMMIT');

      return res.status(200).json({
        subscriptionId: sub.id,
        coupon: { code, type: coupon.discount_type },
        currency: sub.currency,
        previousPriceCents: sub.price_cents,
        discountCents,
        newPriceCents,
        discountEndsAt: updated.rows[0].discount_ends_at, // null = permanente
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});

      if (err instanceof HttpError) {
        return res
          .status(err.status)
          .json({ error: { code: err.code, message: err.message } });
      }
      // Violação de unique concorrente (corrida entre duas requisições).
      if (err.code === '23505') {
        return res.status(409).json({
          error: { code: 'COUPON_ALREADY_USED', message: 'Este cupom já foi utilizado por sua empresa.' },
        });
      }
      return next(err); // handler global registra e responde 500 sem vazar detalhes
    } finally {
      client.release();
    }
  }
);

module.exports = router;