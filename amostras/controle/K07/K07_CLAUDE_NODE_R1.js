/**
 * auth.routes.js — POST /api/auth/login
 * Node.js >= 20 (ESM) | Express 4 | PostgreSQL | argon2 | zod
 *
 * npm i express helmet express-rate-limit pg argon2 zod
 *
 * ---------------------------------------------------------------
 * SCHEMA (PostgreSQL) — referência
 * ---------------------------------------------------------------
 * CREATE TABLE companies (
 *   id UUID PRIMARY KEY,
 *   name TEXT NOT NULL,
 *   status TEXT NOT NULL DEFAULT 'active'          -- active | suspended
 * );
 *
 * CREATE TABLE subscriptions (
 *   id UUID PRIMARY KEY,
 *   company_id UUID NOT NULL REFERENCES companies(id),
 *   status TEXT NOT NULL,                           -- active | past_due | canceled
 *   expires_at TIMESTAMPTZ NOT NULL
 * );
 *
 * CREATE TABLE users (
 *   id UUID PRIMARY KEY,
 *   company_id UUID NOT NULL REFERENCES companies(id),
 *   email TEXT NOT NULL UNIQUE,                     -- sempre armazenado em minúsculas
 *   password_hash TEXT NOT NULL,                    -- argon2id
 *   role TEXT NOT NULL DEFAULT 'member',
 *   is_active BOOLEAN NOT NULL DEFAULT TRUE,
 *   failed_attempts INT NOT NULL DEFAULT 0,
 *   locked_until TIMESTAMPTZ
 * );
 *
 * CREATE TABLE sessions (
 *   token_hash BYTEA PRIMARY KEY,                   -- SHA-256 do token (nunca o token em claro)
 *   user_id UUID NOT NULL REFERENCES users(id),
 *   company_id UUID NOT NULL REFERENCES companies(id),
 *   created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 *   expires_at TIMESTAMPTZ NOT NULL,
 *   ip INET,
 *   user_agent TEXT
 * );
 * CREATE INDEX ON sessions (user_id);
 * CREATE INDEX ON sessions (expires_at);
 */

import crypto from 'node:crypto';
import express from 'express';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import argon2 from 'argon2';
import { z } from 'zod';
import pg from 'pg';

// ---------------------------------------------------------------
// Configuração (A05) — tudo via ambiente, sem segredos no código
// ---------------------------------------------------------------
const IS_PROD = process.env.NODE_ENV === 'production';
const SESSION_TTL_MS = 60 * 60 * 1000 * 8;   // 8 horas
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_MINUTES = 15;
const COOKIE_NAME = IS_PROD ? '__Host-sid' : 'sid'; // __Host- exige Secure + Path=/ + sem Domain

export const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL, // use TLS no ambiente de produção
  max: 20,
  statement_timeout: 5000,
});

// Parâmetros Argon2id (recomendação OWASP: >= 19 MiB, t=2, p=1)
const ARGON_OPTS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };

// Hash falso para equalizar o tempo de resposta quando o usuário não existe (A07 — enumeração)
const DUMMY_HASH = await argon2.hash(crypto.randomBytes(16).toString('hex'), ARGON_OPTS);

// ---------------------------------------------------------------
// Validação de entrada (A03) — rejeita formato inesperado e limita tamanho
// ---------------------------------------------------------------
const loginSchema = z.object({
  email: z.string().trim().toLowerCase().max(254).email(),
  // limite máximo evita DoS por senhas gigantes; mínimo não é checado aqui de propósito
  password: z.string().min(1).max(128),
}).strict();

// ---------------------------------------------------------------
// Rate limiting (A07) — por IP e por e-mail alvo
// ---------------------------------------------------------------
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 50,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req.ip),
  message: { error: 'Muitas tentativas. Tente novamente mais tarde.' },
});

const emailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  // Chave baseada no e-mail informado: protege contra ataque distribuído a uma conta.
  // Em múltiplas instâncias, use um store compartilhado (ex.: Redis).
  keyGenerator: (req) =>
    'login:' + crypto.createHash('sha256').update(String(req.body?.email ?? '').toLowerCase()).digest('hex'),
  message: { error: 'Muitas tentativas. Tente novamente mais tarde.' },
});

// ---------------------------------------------------------------
// Utilitários
// ---------------------------------------------------------------
const sha256 = (v) => crypto.createHash('sha256').update(v).digest();

const INVALID = { error: 'Credenciais inválidas.' }; // mensagem única: não revela se o e-mail existe

function audit(event, data) {
  // A09 — log estruturado de eventos de segurança. NUNCA registrar senha ou token.
  console.info(JSON.stringify({ ts: new Date().toISOString(), event, ...data }));
}

// ---------------------------------------------------------------
// Rota
// ---------------------------------------------------------------
export const authRouter = express.Router();

authRouter.post('/login', ipLimiter, express.json({ limit: '2kb' }), emailLimiter, async (req, res) => {
  // 1) Validação
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Requisição inválida.' });
  const { email, password } = parsed.data;

  const ip = req.ip;
  const userAgent = String(req.get('user-agent') ?? '').slice(0, 255);

  try {
    // 2) Busca parametrizada (A03 — sem concatenação de SQL)
    const { rows } = await pool.query(
      `SELECT u.id, u.company_id, u.email, u.role, u.password_hash, u.is_active,
              u.locked_until, (u.locked_until IS NOT NULL AND u.locked_until > now()) AS is_locked,
              c.status AS company_status,
              EXISTS (
                SELECT 1 FROM subscriptions s
                 WHERE s.company_id = u.company_id
                   AND s.status = 'active'
                   AND s.expires_at > now()
              ) AS has_active_plan
         FROM users u
         JOIN companies c ON c.id = u.company_id
        WHERE u.email = $1
        LIMIT 1`,
      [email],
    );
    const user = rows[0];

    // 3) Verificação de senha sempre executada (tempo constante entre "não existe" e "senha errada")
    const hashToCheck = user?.password_hash ?? DUMMY_HASH;
    const passwordOk = await argon2.verify(hashToCheck, password).catch(() => false);

    // 4) Falha: usuário inexistente, conta bloqueada, inativa ou senha incorreta → mesma resposta
    if (!user || user.is_locked || !user.is_active || !passwordOk) {
      if (user && !user.is_locked) {
        // Contador atômico + bloqueio temporário (A07)
        await pool.query(
          `UPDATE users
              SET failed_attempts = failed_attempts + 1,
                  locked_until = CASE WHEN failed_attempts + 1 >= $2
                                      THEN now() + make_interval(mins => $3)
                                      ELSE locked_until END
            WHERE id = $1`,
          [user.id, MAX_FAILED_ATTEMPTS, LOCK_MINUTES],
        );
      }
      audit('login_failed', { userId: user?.id ?? null, companyId: user?.company_id ?? null, ip, locked: !!user?.is_locked });
      return res.status(401).json(INVALID);
    }

    // 5) Credenciais corretas: só agora verificamos tenant/plano (não vaza informação a quem não autenticou)
    if (user.company_status !== 'active' || !user.has_active_plan) {
      audit('login_denied_plan', { userId: user.id, companyId: user.company_id, ip });
      return res.status(403).json({ error: 'Acesso indisponível. Verifique a assinatura da sua empresa.' });
    }

    // 6) Atualiza hash se os parâmetros de custo mudaram (migração transparente)
    if (argon2.needsRehash(user.password_hash, ARGON_OPTS)) {
      const newHash = await argon2.hash(password, ARGON_OPTS);
      await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, user.id]);
    }

    // 7) Emite token de sessão: 256 bits de entropia, armazenado apenas como hash (A02)
    const token = crypto.randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1', [user.id]);
      await client.query(
        `INSERT INTO sessions (token_hash, user_id, company_id, expires_at, ip, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [sha256(token), user.id, user.company_id, expiresAt, ip, userAgent],
      );
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }

    audit('login_success', { userId: user.id, companyId: user.company_id, ip });

    // 8) Cookie seguro: inacessível a JS (XSS), só HTTPS, não enviado em requisições cross-site (CSRF)
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      secure: IS_PROD,
      sameSite: 'strict',
      path: '/',
      maxAge: SESSION_TTL_MS,
    });
    res.set('Cache-Control', 'no-store');

    return res.status(200).json({
      user: { id: user.id, email: user.email, role: user.role, companyId: user.company_id },
      expiresAt: expiresAt.toISOString(),
    });
  } catch (err) {
    // A09/A05 — loga o detalhe internamente, nunca expõe stack trace ao cliente
    console.error(JSON.stringify({ event: 'login_error', message: err.message }));
    return res.status(500).json({ error: 'Erro interno.' });
  }
});

// ---------------------------------------------------------------
// Exemplo de bootstrap (app.js)
// ---------------------------------------------------------------
// import helmet from 'helmet';
// const app = express();
// app.disable('x-powered-by');
// app.set('trust proxy', 1);          // ajuste ao nº real de proxies, senão req.ip e o rate limit ficam incorretos
// app.use(helmet());                  // CSP, HSTS, noSniff, etc. (A05)
// app.use('/api/auth', authRouter);
// app.listen(process.env.PORT || 3000);