'use strict';

/**
 * POST /auth/login  — autenticação multilocatária (SaaS)
 *
 * Dependências: express helmet express-rate-limit pg argon2 zod
 *
 * Variáveis de ambiente:
 *   DATABASE_URL   (obrigatória)
 *   NODE_ENV       (production | development)
 *
 * Esquema mínimo esperado (PostgreSQL):
 *
 *   CREATE TABLE tenants (
 *     id                    UUID PRIMARY KEY,
 *     status                TEXT NOT NULL,            -- 'active' | 'suspended'
 *     subscription_status   TEXT NOT NULL,            -- 'active' | 'past_due' | 'canceled'
 *     subscription_ends_at  TIMESTAMPTZ
 *   );
 *
 *   CREATE TABLE users (
 *     id               UUID PRIMARY KEY,
 *     tenant_id        UUID NOT NULL REFERENCES tenants(id),
 *     email            TEXT NOT NULL,
 *     password_hash    TEXT NOT NULL,
 *     is_active        BOOLEAN NOT NULL DEFAULT TRUE,
 *     failed_attempts  INT NOT NULL DEFAULT 0,
 *     locked_until     TIMESTAMPTZ
 *   );
 *   -- e-mail único globalmente (login sem identificador de tenant)
 *   CREATE UNIQUE INDEX users_email_uq ON users (lower(email));
 *
 *   CREATE TABLE sessions (
 *     token_hash  CHAR(64) PRIMARY KEY,               -- SHA-256 do token
 *     user_id     UUID NOT NULL REFERENCES users(id),
 *     tenant_id   UUID NOT NULL REFERENCES tenants(id),
 *     created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
 *     expires_at  TIMESTAMPTZ NOT NULL,
 *     ip          INET,
 *     user_agent  TEXT
 *   );
 *
 *   CREATE TABLE auth_audit_log (
 *     id         BIGSERIAL PRIMARY KEY,
 *     tenant_id  UUID,
 *     user_id    UUID,
 *     event      TEXT NOT NULL,
 *     ip         INET,
 *     user_agent TEXT,
 *     created_at TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 */

const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const argon2 = require('argon2');
const { z } = require('zod');

// ───────────────────────── Configuração ─────────────────────────

const IS_PROD = process.env.NODE_ENV === 'production';

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL não definida');
}

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 horas
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_MINUTES = 15;
const COOKIE_NAME = IS_PROD ? '__Host-sid' : 'sid';

// Parâmetros Argon2id (recomendação OWASP: >= 19 MiB, t=2, p=1)
const ARGON_OPTS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PROD ? { rejectUnauthorized: true } : false,
  max: 20,
  statement_timeout: 5000,
});

// Hash "isca" para igualar o tempo de resposta quando o usuário não existe
// (mitiga enumeração de usuários por timing).
const dummyHashPromise = argon2.hash(
  crypto.randomBytes(32).toString('hex'),
  ARGON_OPTS
);

// ───────────────────────── Validação de entrada ─────────────────────────

const loginSchema = z
  .object({
    email: z.string().trim().toLowerCase().email().max(254),
    // Limite superior evita DoS via senhas gigantes no hashing
    password: z.string().min(1).max(128),
  })
  .strict(); // rejeita campos extras (mass assignment)

// ───────────────────────── Funções auxiliares ─────────────────────────

const GENERIC_AUTH_ERROR = { error: 'Credenciais inválidas.' };

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function newSessionToken() {
  // 256 bits de entropia de um CSPRNG
  return crypto.randomBytes(32).toString('base64url');
}

async function audit(event, { tenantId = null, userId = null, req }) {
  try {
    await pool.query(
      `INSERT INTO auth_audit_log (tenant_id, user_id, event, ip, user_agent)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        tenantId,
        userId,
        event,
        req.ip,
        String(req.get('user-agent') || '').slice(0, 255),
      ]
    );
  } catch (err) {
    // Falha de auditoria não deve derrubar o login; nunca logar credenciais.
    console.error('[audit] falha ao registrar evento:', err.code || err.message);
  }
}

async function registerFailure(userId) {
  // Atualização atômica: incrementa e bloqueia ao atingir o limite
  await pool.query(
    `UPDATE users
        SET failed_attempts = failed_attempts + 1,
            locked_until = CASE
              WHEN failed_attempts + 1 >= $2
              THEN now() + make_interval(mins => $3)
              ELSE locked_until
            END
      WHERE id = $1`,
    [userId, MAX_FAILED_ATTEMPTS, LOCK_MINUTES]
  );
}

// ───────────────────────── Rate limiting ─────────────────────────

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20, // por IP
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Muitas tentativas. Tente novamente mais tarde.' },
});

// ───────────────────────── Rota ─────────────────────────

const router = express.Router();

router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    // 1) Validação de entrada
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Requisição inválida.' });
    }
    const { email, password } = parsed.data;

    // 2) Busca do usuário (consulta parametrizada → sem SQL injection)
    const { rows } = await pool.query(
      `SELECT u.id, u.tenant_id, u.password_hash, u.is_active,
              u.locked_until,
              (u.locked_until IS NOT NULL AND u.locked_until > now()) AS is_locked,
              t.status AS tenant_status,
              t.subscription_status,
              t.subscription_ends_at
         FROM users u
         JOIN tenants t ON t.id = u.tenant_id
        WHERE lower(u.email) = $1
        LIMIT 1`,
      [email]
    );
    const user = rows[0];

    // 3) Verificação da senha (sempre executa o hash, mesmo sem usuário)
    const hashToCheck = user ? user.password_hash : await dummyHashPromise;
    let passwordOk = false;
    try {
      passwordOk = await argon2.verify(hashToCheck, password);
    } catch {
      passwordOk = false;
    }

    // 4) Falha genérica: usuário inexistente, senha errada ou conta bloqueada
    //    → mesma resposta (evita enumeração de contas)
    if (!user || user.is_locked || !passwordOk) {
      if (user && !user.is_locked) {
        await registerFailure(user.id);
      }
      await audit(user?.is_locked ? 'login_blocked_locked' : 'login_failed', {
        tenantId: user?.tenant_id,
        userId: user?.id,
        req,
      });
      return res.status(401).json(GENERIC_AUTH_ERROR);
    }

    // 5) Credenciais corretas → verificações de autorização da conta/assinatura
    if (!user.is_active || user.tenant_status !== 'active') {
      await audit('login_denied_inactive', {
        tenantId: user.tenant_id,
        userId: user.id,
        req,
      });
      return res.status(403).json({ error: 'Acesso indisponível para esta conta.' });
    }

    const subscriptionValid =
      user.subscription_status === 'active' &&
      (!user.subscription_ends_at || new Date(user.subscription_ends_at) > new Date());

    if (!subscriptionValid) {
      await audit('login_denied_subscription', {
        tenantId: user.tenant_id,
        userId: user.id,
        req,
      });
      return res
        .status(403)
        .json({ error: 'A assinatura da empresa não está ativa.' });
    }

    // 6) Cria a sessão (token novo a cada login → previne session fixation)
    const token = newSessionToken();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1`,
        [user.id]
      );
      await client.query(
        `INSERT INTO sessions (token_hash, user_id, tenant_id, expires_at, ip, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          hashToken(token), // somente o hash é persistido
          user.id,
          user.tenant_id,
          expiresAt,
          req.ip,
          String(req.get('user-agent') || '').slice(0, 255),
        ]
      );
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    // 7) Atualiza o hash se os parâmetros de custo mudaram (não bloqueia a resposta)
    if (argon2.needsRehash(user.password_hash, ARGON_OPTS)) {
      argon2
        .hash(password, ARGON_OPTS)
        .then((newHash) =>
          pool.query(`UPDATE users SET password_hash = $1 WHERE id = $2`, [
            newHash,
            user.id,
          ])
        )
        .catch((e) => console.error('[rehash] falha:', e.code || e.message));
    }

    await audit('login_success', {
      tenantId: user.tenant_id,
      userId: user.id,
      req,
    });

    // 8) Token entregue em cookie seguro (inacessível ao JavaScript do navegador)
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      secure: IS_PROD,
      sameSite: 'strict',
      path: '/',
      expires: expiresAt,
    });

    res.set('Cache-Control', 'no-store');
    return res.status(200).json({
      user: { id: user.id, tenantId: user.tenant_id },
      expiresAt: expiresAt.toISOString(),
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;

// ───────────────────────── Bootstrap de exemplo ─────────────────────────

if (require.main === module) {
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', 1); // ajuste conforme seu proxy/load balancer (IP real p/ rate limit)
  app.use(helmet());
  app.use(express.json({ limit: '10kb' })); // limita tamanho do corpo

  app.use('/auth', router);

  // Tratador de erros: nunca expõe stack trace nem detalhes internos
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error('[error]', err.code || err.message);
    res.status(500).json({ error: 'Erro interno.' });
  });

  const port = Number(process.env.PORT) || 3000;
  app.listen(port, () => console.log(`API ouvindo na porta ${port}`));
}