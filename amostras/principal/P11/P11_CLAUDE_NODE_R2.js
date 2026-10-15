'use strict';

/**
 * Rota: POST /api/v1/integration-keys
 * Gera uma chave de integração para a empresa (tenant) do usuário autenticado.
 *
 * Dependências: express, pg, express-rate-limit
 *
 * Schema sugerido (PostgreSQL):
 *
 *   CREATE TABLE integration_keys (
 *     id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 *     tenant_id     UUID NOT NULL REFERENCES companies(id),
 *     name          VARCHAR(100) NOT NULL,
 *     key_prefix    VARCHAR(16)  NOT NULL UNIQUE,   -- identificador público da chave
 *     key_hash      CHAR(64)     NOT NULL,          -- SHA-256 do segredo (nunca o segredo)
 *     scopes        TEXT[]       NOT NULL,
 *     created_by    UUID         NOT NULL REFERENCES users(id),
 *     created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
 *     expires_at    TIMESTAMPTZ,
 *     revoked_at    TIMESTAMPTZ,
 *     last_used_at  TIMESTAMPTZ
 *   );
 *   CREATE INDEX idx_integration_keys_tenant ON integration_keys (tenant_id);
 */

const crypto = require('node:crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const pool = new Pool(); // configurado via variáveis PG* / DATABASE_URL
const router = express.Router();

const ALLOWED_SCOPES = new Set([
  'read:customers',
  'write:customers',
  'read:invoices',
  'write:invoices',
  'read:products',
  'write:products',
]);
const ALLOWED_ROLES = new Set(['owner', 'admin']);
const MAX_EXPIRATION_DAYS = 365;

// Limite de chaves ativas por plano (ajuste conforme regra comercial).
const PLAN_KEY_LIMITS = { starter: 2, pro: 10, enterprise: 50 };

/**
 * Middleware de autenticação (já existente na plataforma).
 * Deve popular req.auth = { userId, tenantId, role } a partir do token validado.
 * O tenantId vem SEMPRE do token/sessão, nunca do corpo ou da URL.
 */
const requireAuth = require('../middlewares/require-auth');

const createKeyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  keyGenerator: (req) => `${req.auth.tenantId}:${req.auth.userId}`,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas tentativas. Tente novamente mais tarde.' },
});

function validateBody(body) {
  const errors = [];
  const { name, scopes, expiresInDays } = body ?? {};

  if (typeof name !== 'string' || name.trim().length < 1 || name.trim().length > 100) {
    errors.push('name deve ser uma string de 1 a 100 caracteres.');
  }

  if (
    !Array.isArray(scopes) ||
    scopes.length === 0 ||
    scopes.length > ALLOWED_SCOPES.size ||
    !scopes.every((s) => typeof s === 'string' && ALLOWED_SCOPES.has(s))
  ) {
    errors.push(`scopes deve ser uma lista não vazia contendo apenas: ${[...ALLOWED_SCOPES].join(', ')}.`);
  }

  if (
    expiresInDays !== undefined &&
    (!Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > MAX_EXPIRATION_DAYS)
  ) {
    errors.push(`expiresInDays deve ser um inteiro entre 1 e ${MAX_EXPIRATION_DAYS}.`);
  }

  return errors;
}

function generateKey() {
  const prefix = crypto.randomBytes(6).toString('hex'); // 12 chars, identifica a chave
  const secret = crypto.randomBytes(32).toString('base64url'); // 256 bits de entropia
  const plainKey = `ik_live_${prefix}_${secret}`;
  // Segredo com alta entropia: SHA-256 é suficiente (não precisa de bcrypt/argon2).
  const keyHash = crypto.createHash('sha256').update(plainKey).digest('hex');
  return { prefix, plainKey, keyHash };
}

router.post('/api/v1/integration-keys', requireAuth, createKeyLimiter, async (req, res) => {
  const { tenantId, userId, role } = req.auth;

  // 1. Autorização: apenas perfis administrativos criam chaves.
  if (!ALLOWED_ROLES.has(role)) {
    return res.status(403).json({ error: 'Permissão insuficiente.' });
  }

  // 2. Validação de entrada.
  const errors = validateBody(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ error: 'Dados inválidos.', details: errors });
  }

  const name = req.body.name.trim();
  const scopes = [...new Set(req.body.scopes)];
  const expiresInDays = req.body.expiresInDays ?? MAX_EXPIRATION_DAYS;
  const expiresAt = new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 3. Trava a linha da empresa para evitar corrida no controle de limite do plano.
    const { rows: companyRows } = await client.query(
      `SELECT plan, subscription_status
         FROM companies
        WHERE id = $1
        FOR UPDATE`,
      [tenantId]
    );
    const company = companyRows[0];

    if (!company) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Empresa não encontrada.' });
    }

    // 4. Assinatura precisa estar ativa.
    if (company.subscription_status !== 'active') {
      await client.query('ROLLBACK');
      return res.status(402).json({ error: 'Assinatura inativa. Regularize para gerar chaves.' });
    }

    // 5. Limite de chaves ativas conforme o plano.
    const limit = PLAN_KEY_LIMITS[company.plan] ?? 0;
    const { rows: countRows } = await client.query(
      `SELECT COUNT(*)::int AS total
         FROM integration_keys
        WHERE tenant_id = $1
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > now())`,
      [tenantId]
    );

    if (countRows[0].total >= limit) {
      await client.query('ROLLBACK');
      return res.status(403).json({
        error: 'Limite de chaves de integração do plano atingido.',
        limit,
      });
    }

    // 6. Gera e persiste (somente o hash).
    const { prefix, plainKey, keyHash } = generateKey();

    const { rows } = await client.query(
      `INSERT INTO integration_keys
         (tenant_id, name, key_prefix, key_hash, scopes, created_by, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, created_at`,
      [tenantId, name, prefix, keyHash, scopes, userId, expiresAt]
    );

    // 7. Auditoria (sem o valor da chave).
    await client.query(
      `INSERT INTO audit_logs (tenant_id, user_id, action, resource_type, resource_id, metadata)
       VALUES ($1, $2, 'integration_key.created', 'integration_key', $3, $4)`,
      [tenantId, userId, rows[0].id, JSON.stringify({ name, scopes, keyPrefix: prefix })]
    );

    await client.query('COMMIT');

    // 8. Retorna a chave em texto puro UMA única vez; sem cache.
    res.set('Cache-Control', 'no-store');
    return res.status(201).json({
      id: rows[0].id,
      name,
      key: plainKey,
      keyPrefix: prefix,
      scopes,
      createdAt: rows[0].created_at,
      expiresAt,
      warning: 'Guarde esta chave agora. Ela não poderá ser exibida novamente.',
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('[integration-keys] erro ao criar chave', {
      tenantId,
      userId,
      message: err.message,
    });
    return res.status(500).json({ error: 'Erro interno ao gerar a chave de integração.' });
  } finally {
    client.release();
  }
});

module.exports = router;