'use strict';

/**
 * POST /api/v1/subscription/coupons/redeem
 *
 * Dependências: express, helmet, pg, jsonwebtoken, zod, express-rate-limit
 *
 * Esquema esperado (PostgreSQL) – resumo:
 *
 *   coupons(
 *     id uuid PK, code text UNIQUE NOT NULL,
 *     discount_type text CHECK (discount_type IN ('percent','fixed')),
 *     discount_value integer CHECK (discount_value > 0),   -- percent: 1..100 | fixed: centavos
 *     valid_from timestamptz, valid_until timestamptz,
 *     max_redemptions integer NULL, redemptions_count integer NOT NULL DEFAULT 0,
 *     allowed_plan_ids uuid[] NULL, active boolean NOT NULL DEFAULT true
 *   )
 *   coupon_redemptions(
 *     id uuid PK, coupon_id uuid REFERENCES coupons, company_id uuid NOT NULL,
 *     user_id uuid NOT NULL, redeemed_at timestamptz DEFAULT now(),
 *     UNIQUE (coupon_id, company_id)                         -- 1 resgate por empresa (barreira final)
 *   )
 *   subscriptions(
 *     id uuid PK, company_id uuid NOT NULL, plan_id uuid NOT NULL,
 *     status text, base_price_cents integer NOT NULL,
 *     discount_cents integer NOT NULL DEFAULT 0,
 *     current_price_cents integer NOT NULL, applied_coupon_id uuid NULL
 *   )
 *   audit_log(id bigserial PK, company_id uuid, user_id uuid, action text,
 *             target_id uuid, ip inet, created_at timestamptz DEFAULT now())
 */

const express = require('express');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Configuração (A02/A05: segredos somente via ambiente, falha rápida se ausentes)
// ---------------------------------------------------------------------------
const { DATABASE_URL, JWT_PUBLIC_KEY, JWT_ISSUER, JWT_AUDIENCE } = process.env;
if (!DATABASE_URL || !JWT_PUBLIC_KEY || !JWT_ISSUER || !JWT_AUDIENCE) {
  throw new Error('Variáveis de ambiente obrigatórias não definidas.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: true }, // A02: TLS com verificação de certificado
  max: 20,
  statement_timeout: 5000,
});

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '2kb', strict: true })); // A04/A05: corpo mínimo

// ---------------------------------------------------------------------------
// Erros de domínio
// ---------------------------------------------------------------------------
class HttpError extends Error {
  constructor(status, publicMessage) {
    super(publicMessage);
    this.status = status;
    this.publicMessage = publicMessage;
  }
}
// Mensagem única para qualquer motivo de cupom inválido (A07/A01: evita enumeração de cupons)
const invalidCoupon = () => new HttpError(422, 'Cupom inválido ou indisponível.');

// ---------------------------------------------------------------------------
// A07: Autenticação – a identidade e o tenant vêm EXCLUSIVAMENTE do token validado
// ---------------------------------------------------------------------------
function authenticate(req, res, next) {
  const header = req.get('authorization') || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return next(new HttpError(401, 'Não autenticado.'));
  }
  try {
    const claims = jwt.verify(token, JWT_PUBLIC_KEY, {
      algorithms: ['RS256'], // A02: algoritmo fixado (bloqueia "none"/downgrade)
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    if (!claims.sub || !claims.company_id || !Array.isArray(claims.roles)) {
      throw new Error('claims ausentes');
    }
    req.auth = {
      userId: claims.sub,
      companyId: claims.company_id,
      roles: claims.roles,
    };
    return next();
  } catch {
    return next(new HttpError(401, 'Não autenticado.'));
  }
}

// A01: Autorização por função – somente quem administra o faturamento pode resgatar
const requireRole = (...allowed) => (req, res, next) =>
  req.auth.roles.some((r) => allowed.includes(r))
    ? next()
    : next(new HttpError(403, 'Acesso negado.'));

// ---------------------------------------------------------------------------
// A04/A07: Rate limit por empresa+usuário (mitiga força bruta de códigos)
// ---------------------------------------------------------------------------
const redeemLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.auth.companyId}:${req.auth.userId}`,
  handler: (req, res, next) =>
    next(new HttpError(429, 'Muitas tentativas. Tente novamente mais tarde.')),
});

// ---------------------------------------------------------------------------
// A03: Validação estrita de entrada (allowlist, sem campos extras)
// ---------------------------------------------------------------------------
const redeemSchema = z
  .object({
    code: z
      .string()
      .trim()
      .transform((v) => v.toUpperCase())
      .pipe(z.string().regex(/^[A-Z0-9_-]{4,32}$/)),
  })
  .strict();

// ---------------------------------------------------------------------------
// A04: Cálculo monetário em inteiros (centavos) – nunca confiar em valores do cliente
// ---------------------------------------------------------------------------
function computeDiscountCents(basePriceCents, coupon) {
  let discount;
  if (coupon.discount_type === 'percent') {
    const pct = Math.min(coupon.discount_value, 100);
    discount = Math.floor((basePriceCents * pct) / 100);
  } else {
    discount = coupon.discount_value;
  }
  return Math.min(Math.max(discount, 0), basePriceCents); // nunca negativo nem acima do preço
}

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------
app.post(
  '/api/v1/subscription/coupons/redeem',
  authenticate,
  requireRole('owner', 'billing_admin'),
  redeemLimiter,
  async (req, res, next) => {
    const parsed = redeemSchema.safeParse(req.body);
    if (!parsed.success) return next(new HttpError(400, 'Requisição inválida.'));

    const { code } = parsed.data;
    const { companyId, userId } = req.auth; // A01: NUNCA lido de body/params/query

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 1) Trava a assinatura DO TENANT (filtro por company_id em toda query – A01)
      const subRes = await client.query(
        `SELECT id, plan_id, base_price_cents, applied_coupon_id
           FROM subscriptions
          WHERE company_id = $1 AND status = 'active'
          FOR UPDATE`,
        [companyId]
      );
      const sub = subRes.rows[0];
      if (!sub) throw new HttpError(409, 'Não há assinatura ativa.');
      if (sub.applied_coupon_id) {
        throw new HttpError(409, 'Já existe um cupom aplicado à assinatura.');
      }

      // 2) Busca o cupom (consulta parametrizada – A03)
      const couponRes = await client.query(
        `SELECT id, discount_type, discount_value, valid_from, valid_until,
                allowed_plan_ids
           FROM coupons
          WHERE code = $1 AND active = true`,
        [code]
      );
      const coupon = couponRes.rows[0];
      if (!coupon) throw invalidCoupon();

      const now = new Date();
      if (
        (coupon.valid_from && now < coupon.valid_from) ||
        (coupon.valid_until && now > coupon.valid_until) ||
        (coupon.allowed_plan_ids && !coupon.allowed_plan_ids.includes(sub.plan_id))
      ) {
        throw invalidCoupon();
      }

      // 3) Consumo ATÔMICO do limite global (sem race condition / TOCTOU – A04)
      const bump = await client.query(
        `UPDATE coupons
            SET redemptions_count = redemptions_count + 1
          WHERE id = $1
            AND (max_redemptions IS NULL OR redemptions_count < max_redemptions)
        RETURNING id`,
        [coupon.id]
      );
      if (bump.rowCount === 0) throw invalidCoupon();

      // 4) Registro único por empresa (UNIQUE(coupon_id, company_id) como última barreira)
      try {
        await client.query(
          `INSERT INTO coupon_redemptions (id, coupon_id, company_id, user_id)
           VALUES ($1, $2, $3, $4)`,
          [crypto.randomUUID(), coupon.id, companyId, userId]
        );
      } catch (e) {
        if (e.code === '23505') throw invalidCoupon(); // unique_violation
        throw e;
      }

      // 5) Cálculo server-side e atualização da assinatura
      const discountCents = computeDiscountCents(sub.base_price_cents, coupon);
      const newPriceCents = sub.base_price_cents - discountCents;

      await client.query(
        `UPDATE subscriptions
            SET discount_cents = $1,
                current_price_cents = $2,
                applied_coupon_id = $3
          WHERE id = $4 AND company_id = $5`,
        [discountCents, newPriceCents, coupon.id, sub.id, companyId]
      );

      // 6) A09: trilha de auditoria (sem dados sensíveis; o código do cupom não é logado)
      await client.query(
        `INSERT INTO audit_log (company_id, user_id, action, target_id, ip)
         VALUES ($1, $2, 'coupon.redeemed', $3, $4)`,
        [companyId, userId, coupon.id, req.ip]
      );

      await client.query('COMMIT');

      res.set('Cache-Control', 'no-store');
      return res.status(200).json({
        subscription_id: sub.id,
        currency: 'BRL',
        base_price_cents: sub.base_price_cents,
        discount_cents: discountCents,
        monthly_price_cents: newPriceCents,
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      return next(err);
    } finally {
      client.release();
    }
  }
);

// ---------------------------------------------------------------------------
// A05/A09: tratamento centralizado – detalhes internos só no log, nunca na resposta
// ---------------------------------------------------------------------------
app.use((err, req, res, _next) => {
  const requestId = crypto.randomUUID();
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: err.publicMessage, request_id: requestId });
  }
  console.error(
    JSON.stringify({
      level: 'error',
      request_id: requestId,
      path: req.path,
      company_id: req.auth?.companyId,
      message: err.message, // sem stack/corpo da requisição na resposta
    })
  );
  return res.status(500).json({ error: 'Erro interno.', request_id: requestId });
});

module.exports = app;