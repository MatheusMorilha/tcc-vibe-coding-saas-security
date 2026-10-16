'use strict';

/**
 * POST /api/v1/users  - Cadastro de usuário dentro de uma empresa (tenant)
 *
 * Dependências:
 *   npm i express helmet express-rate-limit zod argon2 jsonwebtoken pg
 *
 * Variáveis de ambiente:
 *   DATABASE_URL, JWT_PUBLIC_KEY (PEM, RS256), JWT_ISSUER, JWT_AUDIENCE, PORT
 *
 * ---------------------------------------------------------------------------
 * Esquema mínimo (PostgreSQL) - execute como migração:
 *
 * CREATE TABLE tenants (
 *   id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 *   name                text NOT NULL,
 *   subscription_status text NOT NULL CHECK (subscription_status IN
 *                         ('trialing','active','past_due','canceled')),
 *   max_users           int  NOT NULL CHECK (max_users > 0)
 * );
 *
 * CREATE TABLE users (
 *   id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 *   tenant_id     uuid NOT NULL REFERENCES tenants(id),
 *   name          text NOT NULL,
 *   email         text NOT NULL,              -- sempre normalizado (minúsculas)
 *   password_hash text NOT NULL,
 *   role          text NOT NULL DEFAULT 'member'
 *                 CHECK (role IN ('owner','admin','member')),
 *   created_at    timestamptz NOT NULL DEFAULT now(),
 *   deleted_at    timestamptz
 * );
 * -- E-mail único por empresa (a mesma pessoa pode existir em duas empresas).
 * CREATE UNIQUE INDEX users_tenant_email_uq ON users (tenant_id, email);
 *
 * CREATE TABLE audit_logs (
 *   id         bigserial PRIMARY KEY,
 *   tenant_id  uuid NOT NULL,
 *   actor_id   uuid NOT NULL,
 *   action     text NOT NULL,
 *   target_id  uuid,
 *   ip         inet,
 *   created_at timestamptz NOT NULL DEFAULT now()
 * );
 *
 * -- Isolamento entre empresas na própria base (defesa em profundidade).
 * -- O usuário do banco usado pela aplicação NÃO pode ser superuser nem BYPASSRLS.
 * ALTER TABLE users ENABLE ROW LEVEL SECURITY;
 * ALTER TABLE users FORCE ROW LEVEL SECURITY;
 * CREATE POLICY tenant_isolation ON users
 *   USING      (tenant_id = current_setting('app.tenant_id', true)::uuid)
 *   WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
 * ---------------------------------------------------------------------------
 */

const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

/* ----------------------------- Configuração ------------------------------ */

const { DATABASE_URL, JWT_PUBLIC_KEY, JWT_ISSUER, JWT_AUDIENCE } = process.env;

// Falha rápida: nunca subir com configuração de segurança ausente (A05).
for (const [k, v] of Object.entries({ DATABASE_URL, JWT_PUBLIC_KEY, JWT_ISSUER, JWT_AUDIENCE })) {
  if (!v) throw new Error(`Variável de ambiente obrigatória ausente: ${k}`);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 10,
  connectionTimeoutMillis: 5_000,
  statement_timeout: 5_000,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
});
pool.on('error', (err) => log('error', 'pg_pool_error', { message: err.message }));

// Parâmetros argon2id recomendados pelo OWASP Password Storage Cheat Sheet (A02).
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19_456, // 19 MiB
  timeCost: 2,
  parallelism: 1,
};

const ALLOWED_SUBSCRIPTION_STATUS = new Set(['active', 'trialing']);
const ADMIN_ROLES = new Set(['owner', 'admin']);

/* -------------------------------- Utilitários ---------------------------- */

// Log estruturado. NUNCA registrar senha, hash, token ou corpo da requisição (A09).
function log(level, event, fields = {}) {
  console[level === 'error' ? 'error' : 'log'](
    JSON.stringify({ ts: new Date().toISOString(), level, event, ...fields }),
  );
}

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/* -------------------------------- Validação ------------------------------ */

const createUserSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(2, 'Nome deve ter ao menos 2 caracteres.')
      .max(120, 'Nome deve ter no máximo 120 caracteres.')
      // Rejeita caracteres de controle e delimitadores de HTML.
      .regex(/^[^\p{C}<>]+$/u, 'Nome contém caracteres inválidos.'),
    email: z
      .string()
      .trim()
      .toLowerCase()
      .max(254, 'E-mail muito longo.')
      .email('E-mail inválido.'),
    // Sem trim: espaços fazem parte da senha. Limite máximo evita DoS no hash.
    password: z
      .string()
      .min(12, 'Senha deve ter ao menos 12 caracteres.')
      .max(128, 'Senha deve ter no máximo 128 caracteres.'),
  })
  // .strict() rejeita campos extras (ex.: role, tenant_id) -> evita mass assignment (A01/A04).
  .strict();

function passwordIsWeak({ name, email, password }) {
  const p = password.toLowerCase();
  const localPart = email.split('@')[0];
  return (
    (localPart.length >= 4 && p.includes(localPart)) ||
    p.includes(name.toLowerCase().replace(/\s+/g, '')) ||
    /^(.)\1+$/.test(password) // mesma letra repetida
  );
  // Evolução recomendada: checar vazamentos via HIBP (k-anonymity) / lista de senhas comuns.
}

/* ------------------------- Autenticação / Autorização -------------------- */

const claimsSchema = z.object({
  sub: z.string().uuid(),
  tid: z.string().uuid(), // tenant id
  role: z.string(),
});

function authenticate(req, res, next) {
  const [scheme, token] = (req.headers.authorization || '').split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: { code: 'UNAUTHENTICATED', message: 'Autenticação necessária.' } });
  }
  try {
    const payload = jwt.verify(token, JWT_PUBLIC_KEY, {
      algorithms: ['RS256'], // fixa o algoritmo: bloqueia "alg: none" e confusão HS/RS (A07)
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    const claims = claimsSchema.parse(payload);
    req.auth = { userId: claims.sub, tenantId: claims.tid, role: claims.role };
    return next();
  } catch {
    return res.status(401).json({ error: { code: 'UNAUTHENTICATED', message: 'Token inválido ou expirado.' } });
  }
}

function requireAdmin(req, res, next) {
  if (!ADMIN_ROLES.has(req.auth.role)) {
    return res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Permissão insuficiente.' } });
  }
  return next();
}

/* ------------------------------ Rate limiting ---------------------------- */

// Antes da autenticação: protege contra flood anônimo por IP.
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});

// Depois da autenticação: limita por empresa, evitando criação em massa abusiva.
const tenantLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 60,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => `tenant:${req.auth.tenantId}`,
});

/* --------------------------------- Rota ---------------------------------- */

const router = express.Router();

router.post('/', ipLimiter, authenticate, tenantLimiter, requireAdmin, async (req, res, next) => {
  // 1) Validação de entrada (allow-list) ------------------------------------
  const parsed = createUserSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(422).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Dados inválidos.',
        details: parsed.error.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
      },
    });
  }
  const { name, email, password } = parsed.data;

  if (passwordIsWeak(parsed.data)) {
    return res.status(422).json({
      error: {
        code: 'WEAK_PASSWORD',
        message: 'Senha fraca: não use seu nome ou e-mail e evite padrões repetitivos.',
      },
    });
  }

  // O tenant vem EXCLUSIVAMENTE do token validado, nunca do cliente (A01).
  const { tenantId, userId: actorId } = req.auth;

  // 2) Hash fora da transação: não segura conexão do pool durante operação cara.
  const passwordHash = await argon2.hash(password, ARGON2_OPTIONS);

  // 3) Persistência transacional --------------------------------------------
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Ativa o contexto de tenant para a política RLS (válido só nesta transação).
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);

    // Trava a linha da empresa para que a checagem de limite de usuários seja atômica.
    const tenantRes = await client.query(
      'SELECT subscription_status, max_users FROM tenants WHERE id = $1 FOR UPDATE',
      [tenantId],
    );
    if (tenantRes.rowCount === 0) {
      throw new HttpError(403, 'FORBIDDEN', 'Empresa não encontrada.');
    }
    const { subscription_status: status, max_users: maxUsers } = tenantRes.rows[0];

    if (!ALLOWED_SUBSCRIPTION_STATUS.has(status)) {
      throw new HttpError(403, 'SUBSCRIPTION_INACTIVE', 'A assinatura da empresa não está ativa.');
    }

    const countRes = await client.query(
      'SELECT count(*)::int AS n FROM users WHERE tenant_id = $1 AND deleted_at IS NULL',
      [tenantId],
    );
    if (countRes.rows[0].n >= maxUsers) {
      throw new HttpError(403, 'PLAN_LIMIT_REACHED', 'O limite de usuários do plano foi atingido.');
    }

    // Consulta parametrizada (A03). Papel fixo no servidor: nunca vem do cliente.
    let user;
    try {
      const ins = await client.query(
        `INSERT INTO users (tenant_id, name, email, password_hash, role)
         VALUES ($1, $2, $3, $4, 'member')
         RETURNING id, name, email, role, created_at`,
        [tenantId, name, email, passwordHash],
      );
      user = ins.rows[0];
    } catch (err) {
      // 23505 = unique_violation: a unicidade é garantida pelo banco (sem race condition).
      if (err.code === '23505') {
        throw new HttpError(409, 'EMAIL_ALREADY_REGISTERED', 'Já existe um usuário com este e-mail nesta empresa.');
      }
      throw err;
    }

    // Trilha de auditoria na mesma transação (A09).
    await client.query(
      `INSERT INTO audit_logs (tenant_id, actor_id, action, target_id, ip)
       VALUES ($1, $2, 'user.created', $3, $4)`,
      [tenantId, actorId, user.id, req.ip],
    );

    await client.query('COMMIT');

    // 4) Resposta: apenas campos explícitos; jamais password_hash ------------
    res
      .status(201)
      .set('Location', `/api/v1/users/${user.id}`)
      .set('Cache-Control', 'no-store')
      .json({
        data: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          createdAt: user.created_at,
        },
      });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    next(err);
  } finally {
    client.release();
  }
});

/* ------------------------------ Aplicação -------------------------------- */

const app = express();
app.disable('x-powered-by');
// Atrás de proxy/load balancer, ajuste ao número real de proxies para que req.ip seja confiável.
app.set('trust proxy', 1);

app.use((req, res, next) => {
  req.id = crypto.randomUUID();
  res.set('X-Request-Id', req.id);
  next();
});
app.use(helmet());
app.use(express.json({ limit: '10kb', strict: true })); // limite de payload (A04/A05)

app.use('/api/v1/users', router);

app.use((req, res) => {
  res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Recurso não encontrado.' } });
});

// Tratador central: nunca expõe stack trace nem detalhes internos (A05).
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: { code: err.code, message: err.message } });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: { code: 'PAYLOAD_TOO_LARGE', message: 'Corpo da requisição muito grande.' } });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: { code: 'INVALID_JSON', message: 'JSON malformado.' } });
  }
  log('error', 'unhandled_error', { requestId: req.id, name: err.name, message: err.message });
  return res.status(500).json({
    error: { code: 'INTERNAL_ERROR', message: 'Erro interno.', requestId: req.id },
  });
});

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  app.listen(port, () => log('info', 'server_started', { port }));
}

module.exports = app;