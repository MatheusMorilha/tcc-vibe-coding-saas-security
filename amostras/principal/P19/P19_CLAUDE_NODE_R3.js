/**
 * auth.routes.js
 * POST /auth/login  { email, password }  ->  { token, tokenType, expiresIn, user }
 *
 * Dependências:
 *   npm i express pg bcrypt jsonwebtoken express-rate-limit
 *
 * Variáveis de ambiente:
 *   DATABASE_URL   string de conexão do PostgreSQL
 *   JWT_SECRET     segredo longo e aleatório (mín. 32 caracteres)
 *   JWT_EXPIRES_IN (opcional) ex.: "15m", "1h" (padrão: 1h)
 *
 * Schema esperado (referência):
 *
 *   CREATE TABLE companies (
 *     id          UUID PRIMARY KEY,
 *     name        TEXT NOT NULL,
 *     is_active   BOOLEAN NOT NULL DEFAULT TRUE
 *   );
 *
 *   CREATE TABLE subscriptions (
 *     id          UUID PRIMARY KEY,
 *     company_id  UUID NOT NULL REFERENCES companies(id),
 *     plan        TEXT NOT NULL,
 *     status      TEXT NOT NULL,           -- 'active' | 'trialing' | 'past_due' | 'canceled'
 *     expires_at  TIMESTAMPTZ
 *   );
 *
 *   CREATE TABLE users (
 *     id             UUID PRIMARY KEY,
 *     company_id     UUID NOT NULL REFERENCES companies(id),
 *     name           TEXT NOT NULL,
 *     email          TEXT NOT NULL,
 *     password_hash  TEXT NOT NULL,
 *     role           TEXT NOT NULL DEFAULT 'member',
 *     is_active      BOOLEAN NOT NULL DEFAULT TRUE,
 *     last_login_at  TIMESTAMPTZ
 *   );
 *   CREATE UNIQUE INDEX users_email_unique ON users (LOWER(email));
 */

'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET ausente ou curto demais (mínimo de 32 caracteres).');
}

const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const JWT_ISSUER = 'saas-gestao-empresarial';
const JWT_AUDIENCE = 'saas-gestao-empresarial-api';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Hash falso usado para igualar o tempo de resposta quando o usuário não existe
// (evita enumeração de e-mails por análise de tempo).
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 12);

// Statuses de assinatura que permitem acesso à plataforma.
const ACTIVE_SUBSCRIPTION_STATUSES = new Set(['active', 'trialing']);

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---------------------------------------------------------------------------
// Rate limiting (mitiga força bruta e credential stuffing)
// ---------------------------------------------------------------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10, // 10 tentativas por IP + e-mail a cada 15 min
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    `${req.ip}:${String(req.body?.email || '').toLowerCase().trim()}`,
  message: { error: 'Muitas tentativas de login. Tente novamente mais tarde.' },
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function validateBody(body) {
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body?.password === 'string' ? body.password : '';

  if (!email || !password) return { error: 'E-mail e senha são obrigatórios.' };
  if (email.length > 254 || !EMAIL_REGEX.test(email)) return { error: 'E-mail inválido.' };
  // bcrypt só considera os primeiros 72 bytes; limitar evita abuso de CPU.
  if (Buffer.byteLength(password, 'utf8') > 72) return { error: 'Senha inválida.' };

  return { email, password };
}

async function findUserWithTenant(email) {
  const { rows } = await pool.query(
    `SELECT
       u.id, u.company_id, u.name, u.email, u.password_hash, u.role, u.is_active,
       c.is_active AS company_active,
       s.plan, s.status AS subscription_status, s.expires_at AS subscription_expires_at
     FROM users u
     JOIN companies c ON c.id = u.company_id
     LEFT JOIN LATERAL (
       SELECT plan, status, expires_at
       FROM subscriptions
       WHERE company_id = u.company_id
       ORDER BY expires_at DESC NULLS FIRST
       LIMIT 1
     ) s ON TRUE
     WHERE LOWER(u.email) = $1
     LIMIT 1`,
    [email]
  );
  return rows[0] || null;
}

function subscriptionIsValid(user) {
  if (!ACTIVE_SUBSCRIPTION_STATUSES.has(user.subscription_status)) return false;
  if (user.subscription_expires_at && new Date(user.subscription_expires_at) < new Date()) {
    return false;
  }
  return true;
}

function issueToken(user) {
  const payload = {
    tid: user.company_id, // tenant id: usar SEMPRE nas queries das rotas protegidas
    role: user.role,
    plan: user.plan,
  };

  return jwt.sign(payload, JWT_SECRET, {
    algorithm: 'HS256',
    subject: user.id,
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    expiresIn: JWT_EXPIRES_IN,
    jwtid: crypto.randomUUID(), // permite revogação/denylist futura
  });
}

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------
const router = express.Router();

router.post('/login', loginLimiter, async (req, res) => {
  try {
    const parsed = validateBody(req.body);
    if (parsed.error) return res.status(400).json({ error: parsed.error });

    const { email, password } = parsed;
    const user = await findUserWithTenant(email);

    // Sempre executa o compare, mesmo sem usuário, para manter tempo constante.
    const passwordOk = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);

    // Mensagem genérica: não revela se o e-mail existe, se a senha está errada
    // ou se a conta está desativada.
    if (!user || !passwordOk || !user.is_active || !user.company_active) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    // Credenciais corretas: só agora é seguro informar sobre a assinatura.
    if (!subscriptionIsValid(user)) {
      return res.status(403).json({
        error: 'A assinatura da empresa está inativa ou expirada. Contate o administrador.',
        code: 'SUBSCRIPTION_INACTIVE',
      });
    }

    const token = issueToken(user);

    // Falha ao registrar o último login não deve impedir a autenticação.
    pool
      .query('UPDATE users SET last_login_at = NOW() WHERE id = $1 AND company_id = $2', [
        user.id,
        user.company_id,
      ])
      .catch((err) => console.error('Falha ao atualizar last_login_at:', err.message));

    res.set('Cache-Control', 'no-store');
    return res.status(200).json({
      token,
      tokenType: 'Bearer',
      expiresIn: JWT_EXPIRES_IN,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        companyId: user.company_id,
        plan: user.plan,
      },
    });
  } catch (err) {
    console.error('Erro no login:', err);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

module.exports = router;

// ---------------------------------------------------------------------------
// Exemplo de uso (app.js)
// ---------------------------------------------------------------------------
// const express = require('express');
// const authRoutes = require('./auth.routes');
//
// const app = express();
// app.set('trust proxy', 1);          // necessário atrás de proxy/load balancer p/ req.ip correto
// app.use(express.json({ limit: '10kb' }));
// app.use('/auth', authRoutes);
// app.listen(3000);