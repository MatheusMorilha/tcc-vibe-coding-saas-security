// routes/integrationKeys.js
'use strict';

const express = require('express');
const crypto = require('node:crypto');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

/*
  Esquema esperado (PostgreSQL):

  CREATE TABLE integration_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    name        TEXT NOT NULL,
    key_prefix  TEXT NOT NULL UNIQUE,      -- identificador público da chave
    key_hash    BYTEA NOT NULL,            -- HMAC-SHA256 do segredo (nunca o segredo)
    scopes      TEXT[] NOT NULL,
    created_by  UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
  );
  CREATE INDEX ON integration_keys (tenant_id) WHERE revoked_at IS NULL;

  CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY, tenant_id UUID NOT NULL, user_id UUID,
    action TEXT NOT NULL, resource_id UUID, created_at TIMESTAMPTZ DEFAULT now()
  );
*/

const ALLOWED_SCOPES = new Set([
  'read:customers', 'write:customers',
  'read:invoices', 'write:invoices',
  'read:reports',
]);

const PEPPER = process.env.API_KEY_PEPPER; // segredo do servidor, fora do banco
if (!PEPPER || PEPPER.length < 32) {
  throw new Error('API_KEY_PEPPER ausente ou curto demais (mín. 32 caracteres).');
}

// ---------- helpers ----------

function requireRole(...roles) {
  return (req, res, next) =>
    roles.includes(req.auth?.role)
      ? next()
      : res.status(403).json({ error: 'Permissão insuficiente.' });
}

function generateKey() {
  const prefix = crypto.randomBytes(6).toString('hex');          // 12 chars
  const secret = crypto.randomBytes(32).toString('base64url');   // 256 bits
  return { prefix, secret, fullKey: `ik_live_${prefix}_${secret}` };
}

function hashSecret(secret) {
  return crypto.createHmac('sha256', PEPPER).update(secret).digest();
}

function validateBody(body) {
  const errors = [];
  const name = typeof body?.name === 'string' ? body.name.trim() : '';
  if (name.length < 1 || name.length > 100) {
    errors.push('"name" deve ter entre 1 e 100 caracteres.');
  }

  const scopes = body?.scopes;
  if (
    !Array.isArray(scopes) || scopes.length === 0 ||
    !scopes.every((s) => typeof s === 'string' && ALLOWED_SCOPES.has(s))
  ) {
    errors.push(`"scopes" deve ser uma lista não vazia de: ${[...ALLOWED_SCOPES].join(', ')}.`);
  }

  let expiresAt = null;
  if (body?.expiresInDays !== undefined) {
    const d = body.expiresInDays;
    if (!Number.isInteger(d) || d < 1 || d > 365) {
      errors.push('"expiresInDays" deve ser um inteiro entre 1 e 365.');
    } else {
      expiresAt = new Date(Date.now() + d * 86_400_000);
    }
  }

  return { errors, value: { name, scopes: [...new Set(scopes || [])], expiresAt } };
}

const createKeyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  keyGenerator: (req) => `${req.auth.tenantId}:${req.auth.userId}`,
  standardHeaders: true,
  legacyHeaders: false,
});

// ---------- rota ----------

router.post(
  '/integration-keys',
  // authenticate deve ser aplicado antes (app.use('/api', authenticate, router))
  requireRole('owner', 'admin'),
  createKeyLimiter,
  async (req, res) => {
    // O tenant vem SEMPRE do token autenticado, nunca do corpo ou da URL.
    const { tenantId, userId } = req.auth;

    const { errors, value } = validateBody(req.body);
    if (errors.length) return res.status(400).json({ errors });

    const { prefix, secret, fullKey } = generateKey();
    const keyHash = hashSecret(secret);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Trava a assinatura do tenant para evitar corrida no limite do plano.
      const { rows: planRows } = await client.query(
        `SELECT s.status, p.max_integration_keys
           FROM subscriptions s
           JOIN plans p ON p.id = s.plan_id
          WHERE s.tenant_id = $1
          FOR UPDATE OF s`,
        [tenantId]
      );
      const plan = planRows[0];

      if (!plan || plan.status !== 'active') {
        await client.query('ROLLBACK');
        return res.status(402).json({ error: 'Assinatura inativa.' });
      }

      const { rows: countRows } = await client.query(
        `SELECT count(*)::int AS total
           FROM integration_keys
          WHERE tenant_id = $1
            AND revoked_at IS NULL
            AND (expires_at IS NULL OR expires_at > now())`,
        [tenantId]
      );

      if (countRows[0].total >= plan.max_integration_keys) {
        await client.query('ROLLBACK');
        return res.status(403).json({
          error: 'Limite de chaves de integração do plano atingido.',
        });
      }

      const { rows } = await client.query(
        `INSERT INTO integration_keys
           (tenant_id, name, key_prefix, key_hash, scopes, created_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, name, key_prefix, scopes, created_at, expires_at`,
        [tenantId, value.name, prefix, keyHash, value.scopes, userId, value.expiresAt]
      );
      const created = rows[0];

      await client.query(
        `INSERT INTO audit_log (tenant_id, user_id, action, resource_id)
         VALUES ($1, $2, 'integration_key.created', $3)`,
        [tenantId, userId, created.id]
      );

      await client.query('COMMIT');

      // A chave completa só é exibida agora; depois disso não é recuperável.
      res.set('Cache-Control', 'no-store');
      return res.status(201).json({
        id: created.id,
        name: created.name,
        scopes: created.scopes,
        createdAt: created.created_at,
        expiresAt: created.expires_at,
        key: fullKey,
        warning: 'Guarde esta chave agora. Ela não será exibida novamente.',
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      // Não registrar corpo da requisição nem a chave nos logs.
      console.error('Falha ao criar chave de integração', {
        tenantId,
        code: err.code,
        message: err.message,
      });
      return res.status(500).json({ error: 'Erro interno.' });
    } finally {
      client.release();
    }
  }
);

module.exports = router;