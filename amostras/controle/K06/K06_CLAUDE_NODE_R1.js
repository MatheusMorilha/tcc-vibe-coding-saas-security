/**
 * POST /api/v1/subscription/coupons/redeem
 *
 * Dependências: express, helmet, express-rate-limit, jsonwebtoken, zod, pg, pino
 *
 * ---------------------------------------------------------------------------
 * ESQUEMA ESPERADO (PostgreSQL)
 * ---------------------------------------------------------------------------
 * CREATE TABLE coupons (
 *   id                 uuid PRIMARY KEY,
 *   code               text NOT NULL UNIQUE,            -- armazenado em MAIÚSCULAS
 *   discount_type      text NOT NULL CHECK (discount_type IN ('percent','fixed')),
 *   discount_value     integer NOT NULL CHECK (discount_value > 0), -- % (1-100) ou centavos
 *   max_redemptions    integer,                          -- NULL = ilimitado
 *   redemptions_count  integer NOT NULL DEFAULT 0,
 *   valid_from         timestamptz NOT NULL,
 *   valid_until        timestamptz NOT NULL,
 *   active             boolean NOT NULL DEFAULT true,
 *   allowed_plan_ids   uuid[],                           -- NULL = todos os planos
 *   CHECK (discount_type <> 'percent' OR discount_value <= 100)
 * );
 *
 * CREATE TABLE subscriptions (
 *   id                  uuid PRIMARY KEY,
 *   company_id          uuid NOT NULL,
 *   plan_id             uuid NOT NULL,
 *   status              text NOT NULL,
 *   base_price_cents    integer NOT NULL CHECK (base_price_cents >= 0),
 *   monthly_price_cents integer NOT NULL CHECK (monthly_price_cents >= 0),
 *   coupon_id           uuid REFERENCES coupons(id)
 * );
 *
 * CREATE TABLE coupon_redemptions (
 *   id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 *   coupon_id   uuid NOT NULL REFERENCES coupons(id),
 *   company_id  uuid NOT NULL,
 *   user_id     uuid NOT NULL,
 *   redeemed_at timestamptz NOT NULL DEFAULT now(),
 *   UNIQUE (coupon_id, company_id)                       -- 1 resgate por empresa
 * );
 *
 * CREATE TABLE audit_log (
 *   id bigserial PRIMARY KEY, company_id uuid, user_id uuid,
 *   action text NOT NULL, details jsonb, ip inet, created_at timestamptz DEFAULT now()
 * );
 *
 * -- Defesa em profundidade (recomendado): Row-Level Security por tenant
 * -- ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
 * -- CREATE POLICY tenant_isolation ON subscriptions
 * --   USING (company_id = current_setting('app.company_id')::uuid);
 * -- (a aplicação deve conectar com um role SEM BYPASSRLS e sem ser dona das tabelas)
 * ---------------------------------------------------------------------------
 */

'use strict';

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const { Pool } = require('pg');
const pino = require('pino');

const log = pino({
  level: process.env.LOG_LEVEL || 'info',
  // A09: nunca registrar credenciais
  redact: ['req.headers.authorization', 'req.headers.cookie'],
});

// ---------------------------------------------------------------------------
// Configuração (A02/A05: segredos via ambiente, falha rápida se ausentes)
// ---------------------------------------------------------------------------
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY;
const JWT_ISSUER = process.env.JWT_ISSUER;
const JWT_AUDIENCE = process.env.JWT_AUDIENCE;
if (!JWT_PUBLIC_KEY || !JWT_ISSUER || !JWT_AUDIENCE || !process.env.DATABASE_URL) {
  throw new Error('Configuração obrigatória ausente (JWT_* / DATABASE_URL).');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  statement_timeout: 5000,
  idle_in_transaction_session_timeout: 10000,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : undefined,
});
pool.on('error', (err) => log.error({ err: err.message }, 'Erro inesperado no pool'));

// ---------------------------------------------------------------------------
// Erro de domínio com mensagem segura para o cliente
// ---------------------------------------------------------------------------
class HttpError extends Error {
  constructor(status, publicMessage) {
    super(publicMessage);
    this.status = status;
    this.publicMessage = publicMessage;
  }
}
// Mensagem única para qualquer falha de validação do cupom (A04: evita enumeração)
const INVALID_COUPON = () => new HttpError(422, 'Cupom inválido ou não aplicável.');

// ---------------------------------------------------------------------------
// Autenticação (A07) – JWT com algoritmo fixado, issuer e audience verificados
// ---------------------------------------------------------------------------
const claimsSchema = z.object({
  sub: z.string().uuid(),
  company_id: z.string().uuid(),
  role: z.enum(['owner', 'billing_admin', 'member']),
});

function authenticate(req, _res, next) {
  try {
    const header = req.get('authorization') || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) throw new Error('missing token');

    const payload = jwt.verify(token, JWT_PUBLIC_KEY, {
      algorithms: ['RS256'], // impede "alg: none" e confusão HS/RS
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    const claims = claimsSchema.parse(payload);
    // O tenant vem EXCLUSIVAMENTE do token assinado, nunca do body/params/query.
    req.auth = { userId: claims.sub, companyId: claims.company_id, role: claims.role };
    next();
  } catch {
    next(new HttpError(401, 'Não autenticado.'));
  }
}

// Autorização (A01): apenas perfis com poder sobre cobrança
function requireRole(...roles) {
  return (req, _res, next) =>
    roles.includes(req.auth.role) ? next() : next(new HttpError(403, 'Acesso negado.'));
}

// ---------------------------------------------------------------------------
// Rate limit (A04/A07): limita tentativas de adivinhação de cupons
// ---------------------------------------------------------------------------
const redeemLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.auth?.companyId}:${req.auth?.userId}`,
  handler: (_req, _res, next) => next(new HttpError(429, 'Muitas tentativas. Tente mais tarde.')),
});
// Limitador por IP aplicado ANTES da autenticação (protege contra flood)
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 50,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, _res, next) => next(new HttpError(429, 'Muitas requisições.')),
});

// ---------------------------------------------------------------------------
// Validação de entrada (A03) – whitelist estrita, rejeita campos extras
// ---------------------------------------------------------------------------
const redeemSchema = z
  .object({
    code: z
      .string()
      .trim()
      .transform((v) => v.toUpperCase())
      .pipe(z.string().regex(/^[A-Z0-9-]{4,32}$/)),
  })
  .strict();

// ---------------------------------------------------------------------------
// Cálculo monetário em centavos inteiros (sem ponto flutuante)
// ---------------------------------------------------------------------------
function computeDiscountedPrice(basePriceCents, type, value) {
  const discount =
    type === 'percent' ? Math.floor((basePriceCents * value) / 100) : value;
  return Math.max(0, basePriceCents - discount);
}

// ---------------------------------------------------------------------------
// Lógica de negócio – transação atômica com bloqueio de linhas (A04: race conditions)
// ---------------------------------------------------------------------------
async function redeemCoupon({ companyId, userId, code, ip }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Contexto de tenant para Row-Level Security (defesa em profundidade)
    await client.query("SELECT set_config('app.company_id', $1, true)", [companyId]);

    // 1) Assinatura da empresa do token (filtro de tenant explícito + lock)
    const subRes = await client.query(
      `SELECT id, plan_id, base_price_cents, coupon_id
         FROM subscriptions
        WHERE company_id = $1 AND status = 'active'
        FOR UPDATE`,
      [companyId]
    );
    if (subRes.rowCount !== 1) throw new HttpError(409, 'Nenhuma assinatura ativa encontrada.');
    const sub = subRes.rows[0];

    if (sub.coupon_id) throw new HttpError(409, 'A assinatura já possui um cupom aplicado.');

    // 2) Cupom (lock para serializar contagem de usos)
    const cRes = await client.query(
      `SELECT id, discount_type, discount_value, max_redemptions, redemptions_count,
              valid_from, valid_until, active, allowed_plan_ids
         FROM coupons
        WHERE code = $1
        FOR UPDATE`,
      [code]
    );
    if (cRes.rowCount !== 1) throw INVALID_COUPON();
    const c = cRes.rows[0];

    const now = new Date();
    const planAllowed = !c.allowed_plan_ids || c.allowed_plan_ids.includes(sub.plan_id);
    const exhausted = c.max_redemptions !== null && c.redemptions_count >= c.max_redemptions;
    if (!c.active || now < c.valid_from || now > c.valid_until || exhausted || !planAllowed) {
      throw INVALID_COUPON();
    }

    // 3) Registra resgate – UNIQUE(coupon_id, company_id) é a barreira final
    try {
      await client.query(
        `INSERT INTO coupon_redemptions (coupon_id, company_id, user_id)
         VALUES ($1, $2, $3)`,
        [c.id, companyId, userId]
      );
    } catch (e) {
      if (e.code === '23505') throw new HttpError(409, 'Este cupom já foi utilizado pela empresa.');
      throw e;
    }

    await client.query(
      `UPDATE coupons SET redemptions_count = redemptions_count + 1 WHERE id = $1`,
      [c.id]
    );

    // 4) Aplica desconto sobre o preço-base (sem empilhar descontos)
    const newPrice = computeDiscountedPrice(sub.base_price_cents, c.discount_type, c.discount_value);
    await client.query(
      `UPDATE subscriptions
          SET monthly_price_cents = $1, coupon_id = $2
        WHERE id = $3 AND company_id = $4`,
      [newPrice, c.id, sub.id, companyId]
    );

    // 5) Auditoria (A09)
    await client.query(
      `INSERT INTO audit_log (company_id, user_id, action, details, ip)
       VALUES ($1, $2, 'coupon.redeemed', $3, $4)`,
      [
        companyId,
        userId,
        JSON.stringify({ couponId: c.id, previousPriceCents: sub.base_price_cents, newPriceCents: newPrice }),
        ip,
      ]
    );

    await client.query('COMMIT');
    return {
      previousMonthlyPriceCents: sub.base_price_cents,
      monthlyPriceCents: newPrice,
      discountCents: sub.base_price_cents - newPrice,
      currency: 'BRL',
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// ---------------------------------------------------------------------------
// Aplicação e rota
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // ajuste conforme a infraestrutura (necessário p/ IP correto)
app.use(helmet());
app.use(express.json({ limit: '1kb', strict: true }));

const router = express.Router();

router.post(
  '/subscription/coupons/redeem',
  ipLimiter,
  authenticate,
  requireRole('owner', 'billing_admin'),
  redeemLimiter,
  async (req, res, next) => {
    try {
      if (!req.is('application/json')) throw new HttpError(415, 'Content-Type inválido.');

      const parsed = redeemSchema.safeParse(req.body);
      if (!parsed.success) throw new HttpError(400, 'Requisição inválida.');

      const result = await redeemCoupon({
        companyId: req.auth.companyId,
        userId: req.auth.userId,
        code: parsed.data.code,
        ip: req.ip,
      });

      res.set('Cache-Control', 'no-store');
      res.status(200).json({
        message: 'Cupom aplicado com sucesso.',
        subscription: {
          monthlyPriceCents: result.monthlyPriceCents,
          previousMonthlyPriceCents: result.previousMonthlyPriceCents,
          discountCents: result.discountCents,
          currency: result.currency,
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

app.use('/api/v1', router);

// Tratamento centralizado de erros (A05/A09): sem stack trace nem detalhes internos
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  if (err instanceof HttpError) {
    if (err.status >= 400 && err.status < 500) {
      log.warn(
        { status: err.status, userId: req.auth?.userId, companyId: req.auth?.companyId, path: req.path },
        'Falha no resgate de cupom'
      );
    }
    return res.status(err.status).json({ error: err.publicMessage });
  }
  if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
    return res.status(400).json({ error: 'Requisição inválida.' });
  }
  log.error({ err: err.message, path: req.path }, 'Erro interno');
  return res.status(500).json({ error: 'Erro interno do servidor.' });
});

module.exports = app;