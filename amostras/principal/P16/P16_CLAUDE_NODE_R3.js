// routes/subscription.coupons.js
'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const pool = require('../db'); // instância do pg.Pool

const router = express.Router();

// ---------- Middlewares ----------

// Assume que authenticate já validou o JWT e populou:
// req.user = { id, companyId, role }
const { authenticate } = require('../middlewares/auth');

const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user?.role)
    ? next()
    : res.status(403).json({ error: 'Permissão insuficiente.' });

// Limita tentativas por usuário (dificulta brute force de códigos)
const redeemLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.user.companyId}:${req.user.id}`,
  message: { error: 'Muitas tentativas. Tente novamente mais tarde.' },
});

// ---------- Validação ----------

const redeemSchema = z
  .object({
    code: z
      .string()
      .trim()
      .min(3)
      .max(32)
      .regex(/^[A-Za-z0-9_-]+$/)
      .transform((v) => v.toUpperCase()),
  })
  .strict(); // rejeita campos extras (ex.: companyId, price, discount)

// ---------- Regras de negócio ----------

class BusinessError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const INVALID_COUPON = () =>
  new BusinessError(422, 'Cupom inválido ou indisponível.');

function calcDiscountCents(basePriceCents, type, value) {
  const raw =
    type === 'percent'
      ? Math.floor((basePriceCents * value) / 100)
      : value;
  return Math.min(raw, basePriceCents); // nunca deixa o preço negativo
}

// ---------- Rota ----------

router.post(
  '/subscription/coupons/redeem',
  authenticate,
  requireRole('owner', 'admin'),
  redeemLimiter,
  async (req, res, next) => {
    const parsed = redeemSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Requisição inválida.' });
    }

    const { code } = parsed.data;
    const { companyId, id: userId } = req.user; // fonte confiável do tenant

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 1) Trava a assinatura da empresa: serializa resgates concorrentes
      const subRes = await client.query(
        `SELECT id, plan_id, base_price_cents, active_coupon_id
           FROM subscriptions
          WHERE company_id = $1 AND status = 'active'
          FOR UPDATE`,
        [companyId]
      );
      const sub = subRes.rows[0];
      if (!sub) throw new BusinessError(404, 'Nenhuma assinatura ativa encontrada.');

      if (sub.active_coupon_id) {
        throw new BusinessError(409, 'A assinatura já possui um cupom aplicado.');
      }

      // 2) Reserva atômica de uma "vaga" no cupom.
      //    Todas as regras de validade ficam na própria cláusula WHERE,
      //    então não há janela entre checar e consumir.
      const couponRes = await client.query(
        `UPDATE coupons
            SET redemptions_count = redemptions_count + 1
          WHERE code = $1
            AND active = true
            AND valid_from <= now()
            AND (valid_until IS NULL OR valid_until > now())
            AND (max_redemptions IS NULL OR redemptions_count < max_redemptions)
            AND (applicable_plans IS NULL OR $2 = ANY(applicable_plans))
        RETURNING id, code, discount_type, discount_value`,
        [code, sub.plan_id]
      );
      const coupon = couponRes.rows[0];
      if (!coupon) throw INVALID_COUPON(); // mensagem única p/ evitar enumeração

      // 3) Calcula o desconto no servidor (em centavos)
      const discountCents = calcDiscountCents(
        sub.base_price_cents,
        coupon.discount_type,
        coupon.discount_value
      );

      // 4) Registra o resgate. A UNIQUE(coupon_id, company_id) impede duplicidade;
      //    em caso de violação, o ROLLBACK desfaz também o incremento do contador.
      await client.query(
        `INSERT INTO coupon_redemptions
           (coupon_id, company_id, subscription_id, redeemed_by, discount_cents)
         VALUES ($1, $2, $3, $4, $5)`,
        [coupon.id, companyId, sub.id, userId, discountCents]
      );

      // 5) Aplica o desconto (filtrando também por company_id, defesa em profundidade)
      await client.query(
        `UPDATE subscriptions
            SET discount_cents = $1, active_coupon_id = $2
          WHERE id = $3 AND company_id = $4`,
        [discountCents, coupon.id, sub.id, companyId]
      );

      await client.query('COMMIT');

      return res.status(200).json({
        coupon: {
          code: coupon.code,
          type: coupon.discount_type,
          value: coupon.discount_value,
        },
        subscription: {
          planId: sub.plan_id,
          basePriceCents: sub.base_price_cents,
          discountCents,
          monthlyPriceCents: sub.base_price_cents - discountCents,
        },
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});

      if (err instanceof BusinessError) {
        return res.status(err.status).json({ error: err.message });
      }
      // Violação de UNIQUE: esta empresa já resgatou este cupom
      if (err.code === '23505') {
        return res.status(409).json({ error: 'Este cupom já foi utilizado pela sua empresa.' });
      }
      return next(err); // erro inesperado vai para o handler global (sem vazar detalhes)
    } finally {
      client.release();
    }
  }
);

module.exports = router;