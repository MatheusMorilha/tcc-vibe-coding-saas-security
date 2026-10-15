'use strict';

/**
 * auth.routes.js
 * Rotas: POST /auth/refresh  e  POST /auth/logout
 *
 * Dependências: express, cookie-parser, jsonwebtoken, pg, express-rate-limit
 *
 * Esquema esperado (PostgreSQL):
 *
 * CREATE TABLE auth_sessions (
 *   id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 *   family_id             UUID        NOT NULL,   -- identifica o "login" (sessão); acompanha toda a cadeia de rotação
 *   tenant_id             UUID        NOT NULL REFERENCES tenants(id),
 *   user_id               UUID        NOT NULL REFERENCES users(id),
 *   token_hash            CHAR(64)    NOT NULL UNIQUE, -- SHA-256 do refresh token (nunca o token em claro)
 *   created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
 *   expires_at            TIMESTAMPTZ NOT NULL,
 *   absolute_expires_at   TIMESTAMPTZ NOT NULL,   -- limite máximo da sessão, mesmo com rotações
 *   revoked_at            TIMESTAMPTZ,
 *   user_agent            TEXT,
 *   ip                    INET
 * );
 * CREATE INDEX ON auth_sessions (family_id, tenant_id);
 * CREATE INDEX ON auth_sessions (tenant_id, user_id);
 *
 * Premissas: users.status = 'active', tenants.status = 'active' e
 * tenants.subscription_status IN ('active','trialing') indicam conta e plano válidos.
 */

const crypto = require('node:crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const JWT_SECRET = process.env.JWT_ACCESS_SECRET; // obrigatório, >= 32 bytes aleatórios
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_ACCESS_SECRET ausente ou fraco.');
}

const ACCESS_TTL = '15m';
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;      // 7 dias (janela deslizante)
const REFRESH_COOKIE = 'refresh_token';
const JWT_OPTS = { issuer: 'saas-gestao', audience: 'saas-gestao-api', algorithm: 'HS256' };

const COOKIE_OPTS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  path: '/auth',
};

/* ------------------------------ helpers ------------------------------ */

const sha256 = (v) => crypto.createHash('sha256').update(v).digest('hex');
const newRefreshToken = () => crypto.randomBytes(48).toString('base64url');

function signAccessToken({ userId, tenantId, familyId }) {
  return jwt.sign({ sub: userId, tid: tenantId, sid: familyId }, JWT_SECRET, {
    ...JWT_OPTS,
    expiresIn: ACCESS_TTL,
  });
}

function setRefreshCookie(res, token, expiresAt) {
  res.cookie(REFRESH_COOKIE, token, { ...COOKIE_OPTS, expires: expiresAt });
}

function clearRefreshCookie(res) {
  res.clearCookie(REFRESH_COOKIE, COOKIE_OPTS);
}

const unauthorized = (res, msg = 'Sessão inválida ou expirada.') =>
  res.status(401).json({ error: 'unauthorized', message: msg });

/* --------------------- middleware de autenticação --------------------- */
/* Valida o access token E confirma que a sessão ainda não foi revogada.   */

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) return unauthorized(res);

    const claims = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_OPTS.issuer,
      audience: JWT_OPTS.audience,
      algorithms: [JWT_OPTS.algorithm],
    });

    const { rowCount } = await pool.query(
      `SELECT 1
         FROM auth_sessions
        WHERE family_id = $1
          AND tenant_id = $2
          AND user_id   = $3
          AND revoked_at IS NULL
          AND expires_at > now()
        LIMIT 1`,
      [claims.sid, claims.tid, claims.sub]
    );
    if (!rowCount) return unauthorized(res);

    // tenant e usuário vêm SEMPRE do token validado, nunca do corpo/URL da requisição
    req.auth = { userId: claims.sub, tenantId: claims.tid, sessionId: claims.sid };
    return next();
  } catch (err) {
    return unauthorized(res);
  }
}

/* ------------------------------ rotas ------------------------------ */

const router = express.Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * POST /auth/refresh
 * Entrada: cookie httpOnly "refresh_token"
 * Saída:   { accessToken, tokenType, expiresIn } + novo refresh token (rotacionado) em cookie
 */
router.post('/refresh', authLimiter, async (req, res) => {
  const presented = req.cookies?.[REFRESH_COOKIE];
  if (typeof presented !== 'string' || presented.length < 32 || presented.length > 256) {
    clearRefreshCookie(res);
    return unauthorized(res);
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // FOR UPDATE evita que duas requisições simultâneas usem o mesmo refresh token
    const { rows } = await client.query(
      `SELECT s.id, s.family_id, s.tenant_id, s.user_id,
              s.expires_at, s.absolute_expires_at, s.revoked_at,
              u.status AS user_status,
              t.status AS tenant_status,
              t.subscription_status
         FROM auth_sessions s
         JOIN users   u ON u.id = s.user_id   AND u.tenant_id = s.tenant_id
         JOIN tenants t ON t.id = s.tenant_id
        WHERE s.token_hash = $1
        FOR UPDATE OF s`,
      [sha256(presented)]
    );

    const session = rows[0];
    if (!session) {
      await client.query('ROLLBACK');
      clearRefreshCookie(res);
      return unauthorized(res);
    }

    // Reuso de token já rotacionado/revogado => possível roubo: derruba toda a sessão
    if (session.revoked_at) {
      await client.query(
        `UPDATE auth_sessions
            SET revoked_at = now()
          WHERE family_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`,
        [session.family_id, session.tenant_id]
      );
      await client.query('COMMIT');
      clearRefreshCookie(res);
      return unauthorized(res);
    }

    const now = new Date();
    const sessionExpired =
      session.expires_at <= now || session.absolute_expires_at <= now;

    // Usuário, empresa e plano precisam continuar válidos a cada renovação
    const accountOk =
      session.user_status === 'active' &&
      session.tenant_status === 'active' &&
      ['active', 'trialing'].includes(session.subscription_status);

    if (sessionExpired || !accountOk) {
      await client.query(
        `UPDATE auth_sessions
            SET revoked_at = now()
          WHERE family_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`,
        [session.family_id, session.tenant_id]
      );
      await client.query('COMMIT');
      clearRefreshCookie(res);
      return unauthorized(res);
    }

    // Rotação: invalida o token atual e emite um novo na mesma família
    const refreshToken = newRefreshToken();
    const newExpiresAt = new Date(
      Math.min(now.getTime() + REFRESH_TTL_MS, session.absolute_expires_at.getTime())
    );

    await client.query(
      `UPDATE auth_sessions SET revoked_at = now() WHERE id = $1 AND tenant_id = $2`,
      [session.id, session.tenant_id]
    );
    await client.query(
      `INSERT INTO auth_sessions
         (family_id, tenant_id, user_id, token_hash, expires_at, absolute_expires_at, user_agent, ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        session.family_id,
        session.tenant_id,
        session.user_id,
        sha256(refreshToken),
        newExpiresAt,
        session.absolute_expires_at,
        (req.get('user-agent') || '').slice(0, 512),
        req.ip,
      ]
    );

    await client.query('COMMIT');

    const accessToken = signAccessToken({
      userId: session.user_id,
      tenantId: session.tenant_id,
      familyId: session.family_id,
    });

    setRefreshCookie(res, refreshToken, newExpiresAt);
    res.set('Cache-Control', 'no-store');
    return res.status(200).json({
      accessToken,
      tokenType: 'Bearer',
      expiresIn: 15 * 60,
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('[auth/refresh]', err.message);
    return res.status(500).json({ error: 'internal_error', message: 'Erro ao renovar sessão.' });
  } finally {
    client.release();
  }
});

/**
 * POST /auth/logout
 * Requer: Authorization: Bearer <accessToken>
 * Corpo opcional: { "allDevices": true } para encerrar todas as sessões do usuário
 * Saída: { success: true, message }
 */
router.post('/logout', authLimiter, requireAuth, async (req, res) => {
  const { userId, tenantId, sessionId } = req.auth;
  const allDevices = req.body?.allDevices === true;

  try {
    if (allDevices) {
      await pool.query(
        `UPDATE auth_sessions
            SET revoked_at = now()
          WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`,
        [tenantId, userId]
      );
    } else {
      await pool.query(
        `UPDATE auth_sessions
            SET revoked_at = now()
          WHERE family_id = $1 AND tenant_id = $2 AND user_id = $3 AND revoked_at IS NULL`,
        [sessionId, tenantId, userId]
      );
    }

    clearRefreshCookie(res);
    res.set('Cache-Control', 'no-store');
    return res.status(200).json({
      success: true,
      message: allDevices
        ? 'Todas as sessões foram encerradas.'
        : 'Sessão encerrada com sucesso.',
    });
  } catch (err) {
    console.error('[auth/logout]', err.message);
    return res.status(500).json({ error: 'internal_error', message: 'Erro ao encerrar sessão.' });
  }
});

module.exports = { router, requireAuth };

/* ---------------------- exemplo de montagem (app.js) ----------------------
const express = require('express');
const cookieParser = require('cookie-parser');
const { router: authRouter } = require('./auth.routes');

const app = express();
app.set('trust proxy', 1);       // necessário para req.ip / rate limit atrás de proxy
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use('/auth', authRouter);
app.listen(3000);
---------------------------------------------------------------------------- */