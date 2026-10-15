// auth.routes.js
// Dependências: express, jsonwebtoken, pg
// Variáveis de ambiente: JWT_ACCESS_SECRET, DATABASE_URL
//
// Tabela esperada (uma única base, isolamento lógico por tenant_id):
//
// CREATE TABLE sessions (
//   id                 UUID PRIMARY KEY,
//   tenant_id          UUID NOT NULL REFERENCES tenants(id),
//   user_id            UUID NOT NULL REFERENCES users(id),
//   family_id          UUID NOT NULL,          -- agrupa a cadeia de rotações
//   refresh_token_hash CHAR(64) NOT NULL UNIQUE,
//   expires_at         TIMESTAMPTZ NOT NULL,
//   revoked_at         TIMESTAMPTZ,
//   replaced_by        UUID,
//   created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
// );
// CREATE INDEX ON sessions (tenant_id, user_id);
// CREATE INDEX ON sessions (family_id);

'use strict';

const crypto = require('node:crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

const ACCESS_TTL_SECONDS = 15 * 60; // 15 minutos
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 dias
const ACTIVE_SUBSCRIPTION_STATUSES = ['active', 'trialing'];

// ---------- Utilitários ----------

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const newRefreshToken = () => crypto.randomBytes(48).toString('base64url');

function signAccessToken({ userId, tenantId, sessionId }) {
  return jwt.sign(
    { sub: userId, tid: tenantId, sid: sessionId },
    process.env.JWT_ACCESS_SECRET,
    { algorithm: 'HS256', expiresIn: ACCESS_TTL_SECONDS }
  );
}

function extractRefreshToken(req) {
  const token = req.body?.refreshToken;
  return typeof token === 'string' && token.length >= 32 && token.length <= 256
    ? token
    : null;
}

// ---------- Middleware de autenticação (access token) ----------

function authenticate(req, res, next) {
  const header = req.get('Authorization') || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Token de acesso ausente.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
      algorithms: ['HS256'],
    });
    req.auth = { userId: payload.sub, tenantId: payload.tid, sessionId: payload.sid };
    return next();
  } catch {
    return res.status(401).json({ error: 'Token de acesso inválido ou expirado.' });
  }
}

// ---------- POST /auth/refresh ----------
// Corpo: { "refreshToken": "..." }
// Retorna novo access token + novo refresh token (rotação).

router.post('/auth/refresh', async (req, res) => {
  const refreshToken = extractRefreshToken(req);
  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token não informado.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Bloqueia a linha para evitar duas renovações concorrentes com o mesmo token.
    const { rows } = await client.query(
      `SELECT id, tenant_id, user_id, family_id, expires_at, revoked_at
         FROM sessions
        WHERE refresh_token_hash = $1
        FOR UPDATE`,
      [sha256(refreshToken)]
    );
    const session = rows[0];

    if (!session) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'Sessão inválida.' });
    }

    // Token já utilizado/revogado sendo reapresentado: possível roubo.
    // Revoga toda a família de sessões derivada dele.
    if (session.revoked_at) {
      await client.query(
        `UPDATE sessions
            SET revoked_at = now()
          WHERE family_id = $1
            AND tenant_id = $2
            AND revoked_at IS NULL`,
        [session.family_id, session.tenant_id]
      );
      await client.query('COMMIT');
      return res.status(401).json({ error: 'Sessão inválida.' });
    }

    if (new Date(session.expires_at) <= new Date()) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'Sessão expirada.' });
    }

    // Revalida usuário, empresa e assinatura, sempre filtrando por tenant_id.
    const { rows: accessRows } = await client.query(
      `SELECT u.id
         FROM users u
         JOIN tenants t ON t.id = u.tenant_id
         JOIN subscriptions s ON s.tenant_id = t.id
        WHERE u.id = $1
          AND u.tenant_id = $2
          AND u.is_active = TRUE
          AND t.is_active = TRUE
          AND s.status = ANY($3)`,
      [session.user_id, session.tenant_id, ACTIVE_SUBSCRIPTION_STATUSES]
    );

    if (accessRows.length === 0) {
      await client.query(
        `UPDATE sessions SET revoked_at = now()
          WHERE family_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`,
        [session.family_id, session.tenant_id]
      );
      await client.query('COMMIT');
      return res.status(403).json({ error: 'Acesso não autorizado para este tenant.' });
    }

    // Rotação: invalida o token atual e emite um novo na mesma família.
    const newToken = newRefreshToken();
    const newSessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + REFRESH_TTL_MS);

    await client.query(
      `INSERT INTO sessions
         (id, tenant_id, user_id, family_id, refresh_token_hash, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [newSessionId, session.tenant_id, session.user_id, session.family_id,
       sha256(newToken), expiresAt]
    );

    await client.query(
      `UPDATE sessions
          SET revoked_at = now(), replaced_by = $1
        WHERE id = $2 AND tenant_id = $3`,
      [newSessionId, session.id, session.tenant_id]
    );

    await client.query('COMMIT');

    const accessToken = signAccessToken({
      userId: session.user_id,
      tenantId: session.tenant_id,
      sessionId: newSessionId,
    });

    res.set('Cache-Control', 'no-store');
    return res.status(200).json({
      accessToken,
      refreshToken: newToken,
      tokenType: 'Bearer',
      expiresIn: ACCESS_TTL_SECONDS,
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('[auth/refresh]', err);
    return res.status(500).json({ error: 'Erro interno ao renovar a sessão.' });
  } finally {
    client.release();
  }
});

// ---------- POST /auth/logout ----------
// Requer Authorization: Bearer <accessToken>
// Corpo opcional: { "allDevices": true } para encerrar todas as sessões do usuário.
// Operação idempotente.

router.post('/auth/logout', authenticate, async (req, res) => {
  const { userId, tenantId, sessionId } = req.auth;
  const allDevices = req.body?.allDevices === true;

  try {
    if (allDevices) {
      await pool.query(
        `UPDATE sessions
            SET revoked_at = now()
          WHERE tenant_id = $1
            AND user_id = $2
            AND revoked_at IS NULL`,
        [tenantId, userId]
      );
    } else {
      // Revoga a família inteira da sessão atual (cadeia de refresh tokens do dispositivo).
      await pool.query(
        `UPDATE sessions
            SET revoked_at = now()
          WHERE tenant_id = $1
            AND user_id = $2
            AND revoked_at IS NULL
            AND family_id = (
              SELECT family_id FROM sessions
               WHERE id = $3 AND tenant_id = $1 AND user_id = $2
            )`,
        [tenantId, userId, sessionId]
      );
    }

    res.set('Cache-Control', 'no-store');
    return res.status(200).json({
      success: true,
      message: allDevices
        ? 'Todas as sessões foram encerradas com sucesso.'
        : 'Sessão encerrada com sucesso.',
    });
  } catch (err) {
    console.error('[auth/logout]', err);
    return res.status(500).json({ error: 'Erro interno ao encerrar a sessão.' });
  }
});

module.exports = router;

// ---------- Exemplo de uso ----------
// const app = express();
// app.use(express.json({ limit: '10kb' }));
// app.use(require('./auth.routes'));
// // Recomendado: aplicar rate limit (ex.: express-rate-limit) em /auth/refresh.
// app.listen(3000);