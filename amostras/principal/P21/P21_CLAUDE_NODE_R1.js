'use strict';

/**
 * routes/session.js
 *
 * POST /auth/refresh -> renova o token de sessão (rotação de refresh token)
 * POST /auth/logout  -> encerra a sessão do usuário
 *
 * Dependências: express, jsonwebtoken, pg, cookie-parser, express-rate-limit
 *
 * Tabela esperada (PostgreSQL):
 *
 *   CREATE TABLE sessions (
 *     id           UUID PRIMARY KEY,
 *     family_id    UUID NOT NULL,          -- cadeia de rotação do mesmo login
 *     tenant_id    UUID NOT NULL,
 *     user_id      UUID NOT NULL,
 *     token_hash   CHAR(64) NOT NULL UNIQUE, -- SHA-256 do refresh token
 *     expires_at   TIMESTAMPTZ NOT NULL,
 *     revoked_at   TIMESTAMPTZ,
 *     replaced_by  UUID,
 *     created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *   CREATE INDEX ON sessions (tenant_id, user_id);
 *   CREATE INDEX ON sessions (family_id);
 */

const crypto = require('crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const ACCESS_TTL_SECONDS = 15 * 60; // 15 minutos
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 dias
const COOKIE_NAME = 'refresh_token';

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  path: '/auth',
};

// ---------------------------------------------------------------------------
// Utilitários
// ---------------------------------------------------------------------------

const sha256 = (value) =>
  crypto.createHash('sha256').update(value).digest('hex');

const generateRefreshToken = () => crypto.randomBytes(48).toString('base64url');

function signAccessToken({ userId, tenantId, role, sessionId }) {
  return jwt.sign(
    { sub: userId, tid: tenantId, role, sid: sessionId },
    process.env.JWT_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: ACCESS_TTL_SECONDS,
      issuer: 'saas-gestao',
      jwtid: crypto.randomUUID(),
    }
  );
}

// Aceita o refresh token via cookie httpOnly (web) ou corpo (clientes mobile/API)
function extractRefreshToken(req) {
  const token = req.cookies?.[COOKIE_NAME] ?? req.body?.refreshToken;
  return typeof token === 'string' && token.length >= 40 && token.length <= 200
    ? token
    : null;
}

// Revoga toda a cadeia de rotação (usado em logout e em detecção de reuso)
async function revokeFamily(client, familyId, tenantId) {
  await client.query(
    `UPDATE sessions
        SET revoked_at = now()
      WHERE family_id = $1
        AND tenant_id = $2
        AND revoked_at IS NULL`,
    [familyId, tenantId]
  );
}

const unauthorized = (res) =>
  res.status(401).json({ error: 'invalid_session', message: 'Sessão inválida ou expirada.' });

// ---------------------------------------------------------------------------
// Rotas
// ---------------------------------------------------------------------------

const router = express.Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * POST /auth/refresh
 * Entrada: refresh token (cookie ou body.refreshToken)
 * Saída:   { accessToken, tokenType, expiresIn } + novo refresh token rotacionado
 */
router.post('/auth/refresh', authLimiter, async (req, res, next) => {
  const presented = extractRefreshToken(req);
  if (!presented) return unauthorized(res);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Bloqueia a linha para impedir uso concorrente do mesmo refresh token
    const { rows } = await client.query(
      `SELECT id, family_id, tenant_id, user_id, expires_at, revoked_at
         FROM sessions
        WHERE token_hash = $1
        FOR UPDATE`,
      [sha256(presented)]
    );
    const session = rows[0];

    if (!session) {
      await client.query('ROLLBACK');
      return unauthorized(res);
    }

    // Token já usado/revogado sendo reapresentado: possível roubo.
    // Invalida toda a cadeia e força novo login.
    if (session.revoked_at) {
      await revokeFamily(client, session.family_id, session.tenant_id);
      await client.query('COMMIT');
      res.clearCookie(COOKIE_NAME, cookieOptions);
      return unauthorized(res);
    }

    if (new Date(session.expires_at) <= new Date()) {
      await client.query('ROLLBACK');
      res.clearCookie(COOKIE_NAME, cookieOptions);
      return unauthorized(res);
    }

    // O tenant vem SEMPRE da sessão persistida, nunca do cliente.
    // Revalida usuário, empresa e assinatura a cada renovação.
    const { rows: ctx } = await client.query(
      `SELECT u.id AS user_id, u.role, u.active AS user_active,
              t.id AS tenant_id, t.active AS tenant_active,
              s.status AS subscription_status, s.current_period_end
         FROM users u
         JOIN tenants t       ON t.id = u.tenant_id
         LEFT JOIN subscriptions s ON s.tenant_id = t.id
        WHERE u.id = $1
          AND u.tenant_id = $2`,
      [session.user_id, session.tenant_id]
    );
    const info = ctx[0];

    const subscriptionOk =
      info &&
      ['active', 'trialing'].includes(info.subscription_status) &&
      new Date(info.current_period_end) > new Date();

    if (!info || !info.user_active || !info.tenant_active || !subscriptionOk) {
      await revokeFamily(client, session.family_id, session.tenant_id);
      await client.query('COMMIT');
      res.clearCookie(COOKIE_NAME, cookieOptions);
      return res.status(403).json({
        error: 'access_denied',
        message: 'Usuário, empresa ou assinatura inativa.',
      });
    }

    // Rotação: invalida o token atual e emite um novo na mesma família
    const newSessionId = crypto.randomUUID();
    const newRefreshToken = generateRefreshToken();
    const newExpiresAt = new Date(Date.now() + REFRESH_TTL_MS);

    await client.query(
      `UPDATE sessions
          SET revoked_at = now(), replaced_by = $1
        WHERE id = $2`,
      [newSessionId, session.id]
    );

    await client.query(
      `INSERT INTO sessions (id, family_id, tenant_id, user_id, token_hash, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        newSessionId,
        session.family_id,
        session.tenant_id,
        session.user_id,
        sha256(newRefreshToken),
        newExpiresAt,
      ]
    );

    await client.query('COMMIT');

    const accessToken = signAccessToken({
      userId: info.user_id,
      tenantId: info.tenant_id,
      role: info.role,
      sessionId: newSessionId,
    });

    res.set('Cache-Control', 'no-store');
    res.cookie(COOKIE_NAME, newRefreshToken, {
      ...cookieOptions,
      maxAge: REFRESH_TTL_MS,
    });

    return res.status(200).json({
      accessToken,
      tokenType: 'Bearer',
      expiresIn: ACCESS_TTL_SECONDS,
      // Para clientes que não usam cookie:
      refreshToken: req.body?.refreshToken ? newRefreshToken : undefined,
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    return next(err);
  } finally {
    client.release();
  }
});

/**
 * POST /auth/logout
 * Encerra a sessão (revoga toda a cadeia de refresh tokens do login atual).
 * Idempotente: sempre confirma, mesmo se a sessão já estiver encerrada.
 */
router.post('/auth/logout', authLimiter, async (req, res, next) => {
  const presented = extractRefreshToken(req);

  // Sempre remove o cookie no cliente
  res.clearCookie(COOKIE_NAME, cookieOptions);
  res.set('Cache-Control', 'no-store');

  if (!presented) {
    return res.status(200).json({ success: true, message: 'Sessão encerrada.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows } = await client.query(
      `SELECT family_id, tenant_id
         FROM sessions
        WHERE token_hash = $1
        FOR UPDATE`,
      [sha256(presented)]
    );

    if (rows[0]) {
      // Escopo pelo tenant da própria sessão: nunca afeta outra empresa
      await revokeFamily(client, rows[0].family_id, rows[0].tenant_id);
    }

    await client.query('COMMIT');
    return res.status(200).json({ success: true, message: 'Sessão encerrada.' });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    return next(err);
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// Exemplo de bootstrap
// ---------------------------------------------------------------------------

if (require.main === module) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '10kb' }));
  app.use(cookieParser());
  app.use(router);

  // Handler de erro: não vaza detalhes internos
  app.use((err, req, res, _next) => {
    console.error(err);
    res.status(500).json({ error: 'internal_error', message: 'Erro interno.' });
  });

  app.listen(process.env.PORT || 3000);
}

module.exports = router;