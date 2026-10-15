/**
 * POST /api/users
 * Cadastro de usuário dentro de uma empresa (tenant) em plataforma SaaS multilocatária.
 *
 * Dependências: npm i express pg bcrypt zod
 *
 * ---------------------------------------------------------------------------
 * Esquema esperado (PostgreSQL):
 *
 * CREATE TABLE tenants (
 *   id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 *   name       TEXT NOT NULL,
 *   max_users  INTEGER NOT NULL,              -- limite de usuários do plano ativo
 *   plan_status TEXT NOT NULL DEFAULT 'active'
 * );
 *
 * CREATE TABLE users (
 *   id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 *   tenant_id     UUID NOT NULL REFERENCES tenants(id),
 *   name          TEXT NOT NULL,
 *   email         TEXT NOT NULL,
 *   password_hash TEXT NOT NULL,
 *   role          TEXT NOT NULL DEFAULT 'member',
 *   created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
 * );
 *
 * -- E-mail único POR empresa (não global), case-insensitive
 * CREATE UNIQUE INDEX users_tenant_email_uq ON users (tenant_id, lower(email));
 * CREATE INDEX users_tenant_idx ON users (tenant_id);
 * ---------------------------------------------------------------------------
 */

const express = require('express');
const bcrypt = require('bcrypt');
const { z } = require('zod');
const { Pool } = require('pg');

// Middlewares que você já deve possuir na plataforma:
//  - authenticate: valida o token e popula req.auth = { userId, tenantId, role }
//  - requireRole:  restringe a rota a determinados papéis
const { authenticate, requireRole } = require('./middlewares/auth');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

const BCRYPT_COST = 12;

// ----------------------------- Validação ----------------------------------
const createUserSchema = z
  .object({
    name: z.string().trim().min(2, 'Nome muito curto').max(120),
    email: z.string().trim().toLowerCase().email('E-mail inválido').max(254),
    password: z
      .string()
      .min(10, 'A senha deve ter no mínimo 10 caracteres')
      .refine((v) => Buffer.byteLength(v, 'utf8') <= 72, 'Senha longa demais (máx. 72 bytes)')
      .refine((v) => /[a-z]/.test(v) && /[A-Z]/.test(v) && /\d/.test(v), {
        message: 'A senha deve conter letras maiúsculas, minúsculas e números',
      }),
  })
  .strict(); // rejeita campos extras (ex.: tenantId, role, id enviados pelo cliente)

// ------------------------------- Rota -------------------------------------
router.post('/users', authenticate, requireRole('owner', 'admin'), async (req, res) => {
  // 1) Validar entrada
  const parsed = createUserSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: 'validation_error',
      details: parsed.error.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
    });
  }
  const { name, email, password } = parsed.data;

  // 2) O tenant vem SEMPRE do contexto autenticado, nunca do body
  const tenantId = req.auth.tenantId;

  // 3) Hash da senha (fora da transação para não segurar conexão/lock)
  const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 4) Trava a linha do tenant para evitar condição de corrida no limite do plano
    const { rows: tenantRows } = await client.query(
      'SELECT max_users, plan_status FROM tenants WHERE id = $1 FOR UPDATE',
      [tenantId]
    );
    const tenant = tenantRows[0];

    if (!tenant || tenant.plan_status !== 'active') {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'plan_inactive', message: 'Assinatura inativa.' });
    }

    // 5) Respeita o limite de usuários do plano
    const { rows: countRows } = await client.query(
      'SELECT count(*)::int AS total FROM users WHERE tenant_id = $1',
      [tenantId]
    );
    if (countRows[0].total >= tenant.max_users) {
      await client.query('ROLLBACK');
      return res.status(402).json({
        error: 'user_limit_reached',
        message: 'Limite de usuários do plano atingido.',
      });
    }

    // 6) Persistir (sempre com tenant_id; consulta parametrizada)
    const { rows } = await client.query(
      `INSERT INTO users (tenant_id, name, email, password_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id, tenant_id, name, email, role, created_at`,
      [tenantId, name, email, passwordHash]
    );

    await client.query('COMMIT');

    const u = rows[0];
    // 7) Retorna os dados do usuário SEM o hash da senha
    return res.status(201).json({
      id: u.id,
      tenantId: u.tenant_id,
      name: u.name,
      email: u.email,
      role: u.role,
      createdAt: u.created_at,
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});

    // Violação do índice único (tenant_id, lower(email))
    if (err.code === '23505') {
      return res.status(409).json({
        error: 'email_in_use',
        message: 'Já existe um usuário com este e-mail nesta empresa.',
      });
    }

    console.error('[POST /users] erro inesperado:', err.message);
    return res.status(500).json({ error: 'internal_error' });
  } finally {
    client.release();
  }
});

module.exports = router;

// ------------------------- Uso no app principal ----------------------------
// const app = express();
// app.use(express.json({ limit: '10kb' }));
// app.use('/api', require('./routes/users'));