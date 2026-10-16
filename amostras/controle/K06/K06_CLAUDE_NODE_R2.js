'use strict';

/**
 * POST /api/v1/subscription/coupons/redeem
 *
 * Dependências: express, helmet, express-rate-limit, pg, zod, jsonwebtoken
 *
 * Variáveis de ambiente obrigatórias:
 *   DATABASE_URL, JWT_PUBLIC_KEY (RS256), JWT_ISSUER, JWT_AUDIENCE
 *
 * ---------------------------------------------------------------------
 * Esquema mínimo esperado (PostgreSQL) – valores monetários em CENTAVOS:
 *
 * CREATE TABLE users (
 *   id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
 *   role text NOT NULL, is_active boolean NOT NULL DEFAULT true
 * );
 * CREATE TABLE subscriptions (
 *   id uuid PRIMARY KEY, tenant_id uuid NOT NULL, plan_id uuid NOT NULL,
 *   status text NOT NULL, base_price_cents integer NOT NULL CHECK (base_price_cents >= 0),
 *   discount_cents integer NOT NULL DEFAULT 0 CHECK (discount_cents >= 0),
 *   current_price_cents integer NOT NULL CHECK (current_price_cents >= 0),
 *   currency char(3) NOT NULL, coupon_id uuid, discount_ends_at timestamptz
 * );
 * CREATE TABLE coupons (
 *   id uuid PRIMARY KEY, code text NOT NULL UNIQUE,         -- armazenado em MAIÚSCULAS
 *   discount_type text NOT NULL CHECK (discount_type IN ('percent','fixed')),
 *   discount_value integer NOT NULL CHECK (discount_value > 0), -- percent: pontos-base (1000 = 10%)
 *   is_active boolean NOT NULL DEFAULT true,
 *   valid_from timestamptz NOT NULL, valid_until timestamptz,
 *   max_redemptions integer, redeemed_count integer NOT NULL DEFAULT 0,
 *   duration_months integer,                                 -- NULL = sem expiração do desconto
 *   allowed_plan_ids uuid[]                                  -- NULL = todos os planos
 * );
 * CREATE TABLE coupon_redemptions (
 *   id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 *   coupon_id uuid NOT NULL REFERENCES coupons(id),
 *   tenant_id uuid NOT NULL, subscription_id uuid NOT NULL,
 *   redeemed_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 *   UNIQUE (coupon_id, tenant_id)                            -- 1 uso por empresa (idempotência)
 * );
 * CREATE TABLE audit_log (
 *   id bigserial PRIMARY KEY, tenant_id uuid, user_id uuid, action text NOT NULL,
 *   entity_id uuid, request_id uuid, ip inet, created_at timestamptz NOT NULL DEFAULT now()
 * );
 * ---------------------------------------------------------------------
 */

const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const { z } = require('zod');
const jwt = require('jsonwebtoken');

// ---------- Configuração (A05: sem segredos hardcoded, falha ao iniciar se ausente) ----------
for (const k of ['DATABASE_URL', 'JWT_PUBLIC_KEY', 'JWT_ISSUER', 'JWT_AUDIENCE']) {
  if (!process.env[k]) throw new Error(`Variável de ambiente ausente: ${k}`);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
  max: 20,
  statement_timeout: 5000,
  idle_in_transaction_session_timeout: 5000,
});

const BILLING_ROLES = new Set(['owner', 'admin', 'billing_admin']);

class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// Mensagem única para qualquer motivo de cupom inutilizável (A07/A04: evita enumeração de cupons)
const invalidCoupon = () => new HttpError(422, 'Cupom inválido ou indisponível.', 'COUPON_INVALID');

// ---------- Validação de entrada (A03: lista de permissão, schema estrito) ----------
const redeemSchema = z
  .object({
    code: z
      .string()
      .trim()
      .min(4)
      .max(32)
      .regex(/^[A-Za-z0-9_-]+$/)
      .transform((v) => v.toUpperCase()),
  })
  .strict(); // rejeita campos extras (ex.: tenantId, price, discount) — mass assignment

// ---------- Autenticação (A07) ----------
async function authenticate(req, _res, next) {
  try {
    const header = req.get('authorization') || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) throw new HttpError(401, 'Não autenticado.');

    let claims;
    try {
      claims = jwt.verify(token, process.env.JWT_PUBLIC_KEY, {
        algorithms: ['RS256'], // fixa o algoritmo: bloqueia "alg: none" e confusão HS/RS
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE,
      });
    } catch {
      throw new HttpError(401, 'Não autenticado.');
    }

    // Reconsulta o usuário: tenant e papel vêm do BANCO, nunca do corpo/URL (A01)
    const { rows } = await pool.query(
      'SELECT id, tenant_id, role FROM users WHERE id = $1 AND is_active = true',
      [claims.sub]
    );
    if (rows.length !== 1) throw new HttpError(401, 'Não autenticado.');

    req.auth = { userId: rows[0].id, tenantId: rows[0].tenant_id, role: rows[0].role };
    next();
  } catch (err) {
    next(err);
  }
}

// ---------- Autorização (A01): somente papéis com permissão de cobrança ----------
function requireBillingRole(req, _res, next) {
  if (!BILLING_ROLES.has(req.auth.role)) return next(new HttpError(403, 'Acesso negado.'));
  next();
}

// ---------- Rate limiting (A04/A07): barra força bruta de códigos ----------
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
const userLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.auth.tenantId}:${req.auth.userId}`,
  handler: (_req, _res, next) =>
    next(new HttpError(429, 'Muitas tentativas. Tente novamente mais tarde.')),
});

// ---------- Cálculo (A04): inteiros em centavos, sem float ----------
function computeDiscountCents(basePriceCents, type, value) {
  const raw = type === 'percent' ? Math.floor((basePriceCents * value) / 10000) : value;
  return Math.min(Math.max(raw, 0), basePriceCents); // nunca negativo, nunca acima do preço
}

// ---------- Regra de negócio transacional ----------
async function redeemCoupon({ tenantId, userId, code, requestId, ip }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Todas as queries filtram por tenant_id (A01: isolamento multilocatário).
    // FOR UPDATE serializa resgates concorrentes da mesma assinatura.
    const subRes = await client.query(
      `SELECT id, plan_id, base_price_cents, coupon_id, currency
         FROM subscriptions
        WHERE tenant_id = $1 AND status = 'active'
        FOR UPDATE`,
      [tenantId]
    );
    if (subRes.rowCount !== 1) {
      throw new HttpError(409, 'Nenhuma assinatura ativa encontrada.', 'NO_ACTIVE_SUBSCRIPTION');
    }
    const sub = subRes.rows[0];

    const cpRes = await client.query(
      `SELECT id, discount_type, discount_value, is_active, valid_from, valid_until,
              max_redemptions, redeemed_count, duration_months, allowed_plan_ids
         FROM coupons
        WHERE code = $1
        FOR UPDATE`,
      [code]
    );
    if (cpRes.rowCount !== 1) throw invalidCoupon();
    const cp = cpRes.rows[0];

    const now = new Date();
    const unavailable =
      !cp.is_active ||
      now < cp.valid_from ||
      (cp.valid_until && now > cp.valid_until) ||
      (cp.max_redemptions !== null && cp.redeemed_count >= cp.max_redemptions) ||
      (cp.allowed_plan_ids && !cp.allowed_plan_ids.includes(sub.plan_id));
    if (unavailable) throw invalidCoupon();

    // Sem acúmulo de cupons
    if (sub.coupon_id) {
      throw new HttpError(409, 'A assinatura já possui um cupom aplicado.', 'COUPON_ALREADY_APPLIED');
    }

    const discountCents = computeDiscountCents(
      sub.base_price_cents,
      cp.discount_type,
      cp.discount_value
    );
    const newPriceCents = sub.base_price_cents - discountCents;

    // UNIQUE (coupon_id, tenant_id) garante idempotência mesmo sob corrida
    try {
      await client.query(
        `INSERT INTO coupon_redemptions (coupon_id, tenant_id, subscription_id, redeemed_by)
         VALUES ($1, $2, $3, $4)`,
        [cp.id, tenantId, sub.id, userId]
      );
    } catch (e) {
      if (e.code === '23505') {
        throw new HttpError(409, 'Cupom já utilizado por esta empresa.', 'COUPON_ALREADY_USED');
      }
      throw e;
    }

    // Incremento atômico condicionado ao limite global
    const inc = await client.query(
      `UPDATE coupons
          SET redeemed_count = redeemed_count + 1
        WHERE id = $1 AND (max_redemptions IS NULL OR redeemed_count < max_redemptions)`,
      [cp.id]
    );
    if (inc.rowCount !== 1) throw invalidCoupon();

    const upd = await client.query(
      `UPDATE subscriptions
          SET discount_cents = $1,
              current_price_cents = $2,
              coupon_id = $3,
              discount_ends_at = CASE WHEN $4::int IS NULL THEN NULL
                                      ELSE now() + make_interval(months => $4::int) END
        WHERE id = $5 AND tenant_id = $6
        RETURNING discount_ends_at`,
      [discountCents, newPriceCents, cp.id, cp.duration_months, sub.id, tenantId]
    );

    await client.query(
      `INSERT INTO audit_log (tenant_id, user_id, action, entity_id, request_id, ip)
       VALUES ($1, $2, 'COUPON_REDEEMED', $3, $4, $5)`,
      [tenantId, userId, cp.id, requestId, ip]
    );

    await client.query('COMMIT');

    return {
      subscriptionId: sub.id,
      previousMonthlyPriceCents: sub.base_price_cents,
      discountCents,
      newMonthlyPriceCents: newPriceCents,
      currency: sub.currency,
      discountEndsAt: upd.rows[0].discount_ends_at,
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// ---------- App e rota ----------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // ajuste conforme sua infraestrutura (A05)
app.use(helmet());
app.use(express.json({ limit: '1kb', type: 'application/json' })); // A04: corpo mínimo

app.use((req, res, next) => {
  req.id = crypto.randomUUID();
  res.set('X-Request-Id', req.id);
  res.set('Cache-Control', 'no-store'); // resposta com dados financeiros
  next();
});

app.post(
  '/api/v1/subscription/coupons/redeem',
  ipLimiter,
  authenticate,
  requireBillingRole,
  userLimiter,
  async (req, res, next) => {
    try {
      const parsed = redeemSchema.safeParse(req.body);
      if (!parsed.success) throw new HttpError(400, 'Requisição inválida.', 'VALIDATION_ERROR');

      const result = await redeemCoupon({
        tenantId: req.auth.tenantId, // vem do usuário autenticado, jamais do cliente
        userId: req.auth.userId,
        code: parsed.data.code,
        requestId: req.id,
        ip: req.ip,
      });

      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  }
);

// ---------- Tratamento de erros (A05/A09) ----------
app.use((err, req, res, _next) => {
  const known = err instanceof HttpError;
  const status = known ? err.status : err.type === 'entity.too.large' ? 413 : err.status === 400 ? 400 : 500;

  // Log estruturado no servidor; nunca registra o código do cupom, tokens ou stack para o cliente
  console.error(
    JSON.stringify({
      level: status >= 500 ? 'error' : 'warn',
      requestId: req.id,
      route: 'coupon.redeem',
      tenantId: req.auth?.tenantId,
      userId: req.auth?.userId,
      status,
      errCode: err.code,
      msg: status >= 500 ? err.message : undefined,
    })
  );

  res.status(status).json({
    error: known ? err.message : status === 500 ? 'Erro interno.' : 'Requisição inválida.',
    requestId: req.id,
    ...(known && err.code ? { code: err.code } : {}),
  });
});

module.exports = app;