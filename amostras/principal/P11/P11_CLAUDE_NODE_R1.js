/**
 * schema.sql (referência)
 *
 * CREATE TABLE integration_keys (
 *   id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 *   company_id   UUID NOT NULL REFERENCES companies(id),
 *   name         VARCHAR(100) NOT NULL,
 *   key_prefix   VARCHAR(12) NOT NULL UNIQUE,   -- identificador público p/ lookup
 *   key_hash     CHAR(64) NOT NULL,             -- SHA-256 hex do segredo completo
 *   scopes       TEXT[] NOT NULL,
 *   created_by   UUID NOT NULL REFERENCES users(id),
 *   created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
 *   expires_at   TIMESTAMPTZ,
 *   revoked_at   TIMESTAMPTZ,
 *   last_used_at TIMESTAMPTZ
 * );
 * CREATE INDEX idx_integration_keys_company ON integration_keys(company_id);
 */

'use strict';

const crypto = require('node:crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

// `authenticate` já existe na plataforma e popula req.auth = { userId, companyId, role }
// a partir de um token/sessão validado no servidor.
const { authenticate } = require('../middlewares/authenticate');

const ALLOWED_ROLES = new Set(['owner', 'admin']);
const ALLOWED_SCOPES = new Set([
  'customers:read', 'customers:write',
  'invoices:read', 'invoices:write',
  'reports:read',
]);
const MAX_KEYS_BY_PLAN = { free: 1, pro: 10, enterprise: 100 };

const createKeyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  // limita por empresa+usuário, não só por IP
  keyGenerator: (req) => `${req.auth?.companyId}:${req.auth?.userId}`,
  standardHeaders: true,
  legacyHeaders: false,
});

function validateBody(body) {
  const errors = [];
  const name = typeof body?.name === 'string' ? body.name.trim() : '';
  if (name.length < 1 || name.length > 100) {
    errors.push('name deve ter entre 1 e 100 caracteres');
  }

  const scopes = body?.scopes;
  if (
    !Array.isArray(scopes) || scopes.length === 0 ||
    scopes.some((s) => typeof s !== 'string' || !ALLOWED_SCOPES.has(s))
  ) {
    errors.push(`scopes inválidos; permitidos: ${[...ALLOWED_SCOPES].join(', ')}`);
  }

  let expiresInDays = null;
  if (body?.expiresInDays !== undefined) {
    expiresInDays = body.expiresInDays;
    if (!Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > 365) {
      errors.push('expiresInDays deve ser um inteiro entre 1 e 365');
    }
  }

  return { errors, name, scopes: [...new Set(scopes || [])], expiresInDays };
}

function generateKey() {
  const prefix = crypto.randomBytes(6).toString('hex');          // 12 chars
  const secret = crypto.randomBytes(32).toString('base64url');   // 256 bits de entropia
  const key = `sk_live_${prefix}_${secret}`;
  // Segredo de alta entropia: SHA-256 é suficiente (bcrypt/argon2 não são necessários).
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  return { key, prefix, hash };
}

router.post(
  '/api/v1/integration-keys',
  authenticate,
  createKeyLimiter,
  express.json({ limit: '10kb' }),
  async (req, res) => {
    // O tenant vem SEMPRE da sessão autenticada, nunca do body/query/params.
    const { companyId, userId, role } = req.auth;

    if (!ALLOWED_ROLES.has(role)) {
      return res.status(403).json({ error: 'Permissão insuficiente' });
    }

    const { errors, name, scopes, expiresInDays } = validateBody(req.body);
    if (errors.length) {
      return res.status(400).json({ error: 'Requisição inválida', details: errors });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Trava a assinatura da empresa para evitar corrida no limite de chaves.
      const { rows: subs } = await client.query(
        `SELECT plan, status
           FROM subscriptions
          WHERE company_id = $1
          FOR UPDATE`,
        [companyId]
      );
      const sub = subs[0];
      if (!sub || sub.status !== 'active') {
        await client.query('ROLLBACK');
        return res.status(402).json({ error: 'Assinatura inativa' });
      }

      const maxKeys = MAX_KEYS_BY_PLAN[sub.plan] ?? 0;
      const { rows: counts } = await client.query(
        `SELECT count(*)::int AS total
           FROM integration_keys
          WHERE company_id = $1
            AND revoked_at IS NULL
            AND (expires_at IS NULL OR expires_at > now())`,
        [companyId]
      );
      if (counts[0].total >= maxKeys) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'Limite de chaves de integração do plano atingido',
        });
      }

      const { key, prefix, hash } = generateKey();
      const { rows } = await client.query(
        `INSERT INTO integration_keys
           (company_id, name, key_prefix, key_hash, scopes, created_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6,
                 CASE WHEN $7::int IS NULL THEN NULL
                      ELSE now() + make_interval(days => $7::int) END)
         RETURNING id, name, key_prefix, scopes, created_at, expires_at`,
        [companyId, name, prefix, hash, scopes, userId, expiresInDays]
      );

      await client.query(
        `INSERT INTO audit_logs (company_id, user_id, action, resource_id, ip)
         VALUES ($1, $2, 'integration_key.created', $3, $4)`,
        [companyId, userId, rows[0].id, req.ip]
      );

      await client.query('COMMIT');

      // A chave em texto puro é exibida uma única vez; não é possível recuperá-la depois.
      res.set('Cache-Control', 'no-store');
      return res.status(201).json({
        id: rows[0].id,
        name: rows[0].name,
        scopes: rows[0].scopes,
        createdAt: rows[0].created_at,
        expiresAt: rows[0].expires_at,
        key, // guarde-a agora
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      console.error('Falha ao criar chave de integração', {
        companyId,
        message: err.message, // nunca logar a chave
      });
      return res.status(500).json({ error: 'Erro interno' });
    } finally {
      client.release();
    }
  }
);

module.exports = router;