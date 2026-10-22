'use strict';

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const pino = require('pino');

const log = pino({ redact: ['req.headers.authorization', '*.password', '*.password_hash'] });

// ---------- Configuração (A05: sem segredos hardcoded, falha se ausentes) ----------
const { DATABASE_URL, JWT_PUBLIC_KEY, JWT_ISSUER, JWT_AUDIENCE } = process.env;
if (!DATABASE_URL || !JWT_PUBLIC_KEY || !JWT_ISSUER || !JWT_AUDIENCE) {
  throw new Error('Variáveis de ambiente obrigatórias ausentes.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
});

// Parâmetros recomendados pela OWASP para Argon2id
const ARGON2_OPTS = {
  type: argon2.argon2id,
  memoryCost: 19456, // 19 MiB
  timeCost: 2,
  parallelism: 1,
};

// ---------- Validação (A03/A04) ----------
const createUserSchema = z
  .object({
    name: z.string().trim().min(2).max(120),
    email: z.string().trim().toLowerCase().email().max(254),
    // NIST 800-63B: tamanho mínimo e máximo, sem regras de composição arbitrárias
    password: z.string().min(12).max(128),
  })
  .strict(); // rejeita campos extras (tenant_id, role, etc.)

// ---------- Autenticação e autorização (A01/A07) ----------
function authenticate(req, res, next) {
  const header = req.get('authorization') || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  try {
    const claims = jwt.verify(token, JWT_PUBLIC_KEY, {
      algorithms: ['RS256'], // fixa o algoritmo, evitando "alg: none" e confusão HS/RS
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    if (!claims.sub || !claims.tenant_id || !claims.role) throw new Error('claims');
    req.auth = { userId: claims.sub, tenantId: claims.tenant_id, role: claims.role };
    next();
  } catch {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
}

function requireRole(...roles) {
  return (req, res, next) =>
    roles.includes(req.auth.role)
      ? next()
      : res.status(403).json({ error: 'Acesso negado.' });
}

// ---------- App ----------
const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '10kb' })); // limita tamanho do body

// Rate limit específico (A07): protege contra abuso e enumeração
const createUserLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

app.post(
  '/api/v1/users',
  createUserLimiter,
  authenticate,
  requireRole('admin'),
  async (req, res, next) => {
    // 1. Validação de entrada
    const parsed = createUserSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Dados inválidos.',
        details: parsed.error.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
      });
    }
    const { name, email, password } = parsed.data;
    const tenantId = req.auth.tenantId; // sempre do token, nunca do body

    let client;
    try {
      // 2. Hash fora da transação para não segurar conexão/lock durante operação cara
      const passwordHash = await argon2.hash(password, ARGON2_OPTS);

      client = await pool.connect();
      await client.query('BEGIN');

      // 3. Lock na linha do tenant: serializa cadastros concorrentes e valida o plano
      const { rows: tenantRows } = await client.query(
        'SELECT max_users, plan_active FROM tenants WHERE id = $1 FOR UPDATE',
        [tenantId]
      );
      const tenant = tenantRows[0];
      if (!tenant || !tenant.plan_active) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'Assinatura inativa.' });
      }

      const { rows: countRows } = await client.query(
        'SELECT COUNT(*)::int AS total FROM users WHERE tenant_id = $1',
        [tenantId]
      );
      if (countRows[0].total >= tenant.max_users) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'Limite de usuários do plano atingido.' });
      }

      // 4. Inserção parametrizada; unicidade garantida pelo índice (sem race condition)
      const { rows } = await client.query(
        `INSERT INTO users (tenant_id, name, email, password_hash)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (tenant_id, email) DO NOTHING
         RETURNING id, tenant_id, name, email, role, created_at`,
        [tenantId, name, email, passwordHash]
      );

      if (rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'E-mail já cadastrado.' });
      }

      await client.query('COMMIT');

      // 5. Auditoria sem dados sensíveis (A09)
      log.info(
        { event: 'user.created', actor: req.auth.userId, tenantId, newUserId: rows[0].id },
        'Usuário criado'
      );

      // 6. Resposta apenas com campos explícitos (nunca password_hash)
      const u = rows[0];
      return res
        .status(201)
        .location(`/api/v1/users/${u.id}`)
        .json({
          id: u.id,
          name: u.name,
          email: u.email,
          role: u.role,
          createdAt: u.created_at,
        });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      next(err);
    } finally {
      if (client) client.release();
    }
  }
);

// ---------- Tratamento de erros (A05/A09): sem vazar stack ou detalhes internos ----------
app.use((err, req, res, _next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'JSON inválido.' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Requisição muito grande.' });
  }
  log.error({ err: { message: err.message, code: err.code }, path: req.path }, 'Erro interno');
  res.status(500).json({ error: 'Erro interno do servidor.' });
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => log.info(`API ouvindo na porta ${port}`));