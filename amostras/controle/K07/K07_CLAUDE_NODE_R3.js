/**
 * auth.routes.js
 * POST /auth/login  { email, password }
 *
 * Dependências: express, helmet, express-rate-limit, pg, argon2, zod
 *
 * Esquema SQL assumido (PostgreSQL):
 *
 * CREATE TABLE tenants (
 *   id                   UUID PRIMARY KEY,
 *   status               TEXT NOT NULL,            -- 'active' | 'suspended'
 *   subscription_status  TEXT NOT NULL             -- 'active' | 'trialing' | 'past_due' | 'canceled'
 * );
 *
 * CREATE TABLE users (
 *   id               UUID PRIMARY KEY,
 *   tenant_id        UUID NOT NULL REFERENCES tenants(id),
 *   email            CITEXT NOT NULL UNIQUE,       -- e-mail único na plataforma
 *   password_hash    TEXT NOT NULL,                -- Argon2id
 *   role             TEXT NOT NULL,
 *   is_active        BOOLEAN NOT NULL DEFAULT TRUE,
 *   failed_attempts  INT NOT NULL DEFAULT 0,
 *   locked_until     TIMESTAMPTZ
 * );
 *
 * CREATE TABLE sessions (
 *   token_hash  CHAR(64) PRIMARY KEY,              -- SHA-256 do token (o token em claro nunca é salvo)
 *   user_id     UUID NOT NULL REFERENCES users(id),
 *   tenant_id   UUID NOT NULL REFERENCES tenants(id),
 *   created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
 *   expires_at  TIMESTAMPTZ NOT NULL,
 *   ip          INET,
 *   user_agent  TEXT
 * );
 * CREATE INDEX ON sessions (user_id);
 * CREATE INDEX ON sessions (expires_at);
 */

'use strict';

const crypto = require('node:crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const argon2 = require('argon2');
const { z } = require('zod');
const { Pool } = require('pg');

// ---------------------------------------------------------------------------
// Configuração (falha rápida se algo essencial estiver ausente)
// ---------------------------------------------------------------------------
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL não definida');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
});

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 horas
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_MINUTES = 15;
const COOKIE_NAME = '__Host-session'; // prefixo __Host- exige Secure, Path=/ e sem Domain

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456, // ~19 MiB (recomendação OWASP)
  timeCost: 2,
  parallelism: 1,
};

// Hash falso para igualar o tempo de resposta quando o e-mail não existe
// (mitiga enumeração de usuários por timing).
let DUMMY_HASH;
const dummyHashReady = argon2
  .hash(crypto.randomBytes(16).toString('hex'), ARGON2_OPTIONS)
  .then((h) => { DUMMY_HASH = h; });

// ---------------------------------------------------------------------------
// Validação de entrada
// ---------------------------------------------------------------------------
const loginSchema = z
  .object({
    email: z.string().trim().toLowerCase().email().max(254),
    // Limite máximo evita DoS por senhas gigantes no hashing
    password: z.string().min(1).max(128),
  })
  .strict(); // rejeita campos extras

// ---------------------------------------------------------------------------
// Rate limiting por IP (em produção use um store compartilhado, ex.: Redis,
// e configure `app.set('trust proxy', ...)` corretamente atrás de proxy/LB)
// ---------------------------------------------------------------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas tentativas. Tente novamente mais tarde.' },
});

// ---------------------------------------------------------------------------
// Utilitários
// ---------------------------------------------------------------------------
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

// Log de segurança estruturado: nunca registrar senha, token ou hash.
function securityLog(event, data) {
  console.info(JSON.stringify({ ts: new Date().toISOString(), event, ...data }));
}

const GENERIC_AUTH_ERROR = { error: 'Credenciais inválidas.' };

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------
const router = express.Router();

router.post('/login', loginLimiter, async (req, res) => {
  const ip = req.ip;
  const userAgent = String(req.get('user-agent') || '').slice(0, 255);

  // 1) Validação de entrada
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Requisição inválida.' });
  }
  const { email, password } = parsed.data;

  try {
    await dummyHashReady;

    // 2) Busca o usuário (consulta parametrizada -> sem SQL Injection)
    const { rows } = await pool.query(
      `SELECT u.id, u.tenant_id, u.email, u.role, u.password_hash, u.is_active,
              u.locked_until,
              t.status AS tenant_status,
              t.subscription_status
         FROM users u
         JOIN tenants t ON t.id = u.tenant_id
        WHERE u.email = $1`,
      [email]
    );
    const user = rows[0];

    // 3) Sempre executa uma verificação Argon2 (real ou falsa) para manter
    //    tempo de resposta uniforme.
    const hashToVerify = user ? user.password_hash : DUMMY_HASH;
    let passwordOk = false;
    try {
      passwordOk = await argon2.verify(hashToVerify, password);
    } catch {
      passwordOk = false; // hash malformado: trata como falha
    }

    const isLocked = user && user.locked_until && user.locked_until > new Date();

    // 4) Falha de autenticação (mensagem genérica, idêntica para: e-mail
    //    inexistente, senha errada e conta bloqueada)
    if (!user || !passwordOk || isLocked) {
      if (user && !isLocked) {
        // Incremento atômico; bloqueia temporariamente ao atingir o limite
        await pool.query(
          `UPDATE users
              SET failed_attempts = CASE WHEN failed_attempts + 1 >= $2 THEN 0
                                         ELSE failed_attempts + 1 END,
                  locked_until    = CASE WHEN failed_attempts + 1 >= $2
                                         THEN now() + make_interval(mins => $3)
                                         ELSE locked_until END
            WHERE id = $1`,
          [user.id, MAX_FAILED_ATTEMPTS, LOCK_MINUTES]
        );
      }
      securityLog('auth.login.failed', {
        userId: user?.id ?? null,
        tenantId: user?.tenant_id ?? null,
        locked: Boolean(isLocked),
        ip,
      });
      return res.status(401).json(GENERIC_AUTH_ERROR);
    }

    // 5) Credenciais corretas: verifica estado da conta, da empresa e do plano
    if (!user.is_active || user.tenant_status !== 'active') {
      securityLog('auth.login.denied_inactive', {
        userId: user.id, tenantId: user.tenant_id, ip,
      });
      return res.status(403).json({ error: 'Acesso não autorizado.' });
    }
    if (!['active', 'trialing'].includes(user.subscription_status)) {
      securityLog('auth.login.denied_subscription', {
        userId: user.id, tenantId: user.tenant_id, ip,
      });
      return res
        .status(403)
        .json({ error: 'Assinatura inativa. Contate o administrador da sua empresa.' });
    }

    // 6) Atualiza hash se os parâmetros do Argon2 foram reforçados
    if (argon2.needsRehash(user.password_hash, ARGON2_OPTIONS)) {
      const newHash = await argon2.hash(password, ARGON2_OPTIONS);
      await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, user.id]);
    }

    // 7) Zera contador de falhas e cria a sessão (token de 256 bits, CSPRNG).
    //    Apenas o hash do token é persistido.
    const token = crypto.randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1',
        [user.id]
      );
      await client.query(
        `INSERT INTO sessions (token_hash, user_id, tenant_id, expires_at, ip, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [sha256(token), user.id, user.tenant_id, expiresAt, ip, userAgent]
      );
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    // 8) Entrega do token em cookie seguro (inacessível a JavaScript)
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      secure: true,       // somente HTTPS
      sameSite: 'strict', // mitiga CSRF
      path: '/',
      expires: expiresAt,
    });
    res.set('Cache-Control', 'no-store');

    securityLog('auth.login.success', { userId: user.id, tenantId: user.tenant_id, ip });

    // Nunca retorne hash, flags internas ou o token no corpo
    return res.status(200).json({
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        tenantId: user.tenant_id,
      },
      expiresAt: expiresAt.toISOString(),
    });
  } catch (err) {
    // Sem vazar detalhes internos ao cliente (A05/A09)
    console.error('auth.login.error', { message: err.message, ip });
    return res.status(500).json({ error: 'Erro interno.' });
  }
});

module.exports = { authRouter: router };

// ---------------------------------------------------------------------------
// Exemplo de bootstrap (app.js)
// ---------------------------------------------------------------------------
/*
const express = require('express');
const helmet = require('helmet');
const { authRouter } = require('./auth.routes');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);          // ajuste conforme sua infraestrutura
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use('/auth', authRouter);

app.listen(process.env.PORT || 3000);
*/