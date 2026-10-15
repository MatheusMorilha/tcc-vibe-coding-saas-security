'use strict';

/**
 * Cadastro de usuário em plataforma SaaS multilocatária (base compartilhada).
 *
 * Dependências: express, pg, bcrypt, zod, jsonwebtoken, express-rate-limit
 *
 * Esquema esperado (PostgreSQL):
 *
 *   CREATE TABLE tenants (
 *     id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 *     name text NOT NULL
 *   );
 *
 *   CREATE TABLE subscriptions (
 *     tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
 *     status text NOT NULL,            -- 'active', 'past_due', 'canceled'...
 *     max_users integer NOT NULL
 *   );
 *
 *   CREATE TABLE users (
 *     id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 *     tenant_id uuid NOT NULL REFERENCES tenants(id),
 *     name text NOT NULL,
 *     email text NOT NULL,
 *     password_hash text NOT NULL,
 *     role text NOT NULL DEFAULT 'member',
 *     created_at timestamptz NOT NULL DEFAULT now()
 *   );
 *
 *   -- Unicidade do e-mail por empresa (case-insensitive)
 *   CREATE UNIQUE INDEX users_tenant_email_uq ON users (tenant_id, lower(email));
 */

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

const BCRYPT_COST = 12;

/* ------------------------------------------------------------------ */
/* Autenticação / autorização                                          */
/* ------------------------------------------------------------------ */

// O tenant vem SEMPRE do token validado, nunca do corpo da requisição.
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.auth = {
      userId: payload.sub,
      tenantId: payload.tenantId,
      role: payload.role,
    };
    return next();
  } catch {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.auth.role)) {
      return res.status(403).json({ error: 'Sem permissão para esta ação.' });
    }
    return next();
  };
}

/* ------------------------------------------------------------------ */
/* Validação                                                           */
/* ------------------------------------------------------------------ */

// .strict() rejeita campos extras (ex.: tenantId, role) -> evita mass assignment
const createUserSchema = z
  .object({
    name: z.string().trim().min(2).max(120),
    email: z.string().trim().toLowerCase().email().max(254),
    password: z.string().min(10).max(128),
  })
  .strict();

const createUserLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

/* ------------------------------------------------------------------ */
/* Rota                                                                */
/* ------------------------------------------------------------------ */

router.post(
  '/api/users',
  createUserLimiter,
  authenticate,
  requireRole('owner', 'admin'),
  async (req, res, next) => {
    const parsed = createUserSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Dados inválidos.',
        details: parsed.error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        })),
      });
    }

    const { name, email, password } = parsed.data;
    const { tenantId } = req.auth;

    // Hash fora da transação para não segurar locks durante operação custosa
    const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Trava a assinatura da empresa: serializa cadastros concorrentes
      // e impede estourar o limite de usuários do plano (race condition).
      const sub = await client.query(
        `SELECT status, max_users
           FROM subscriptions
          WHERE tenant_id = $1
          FOR UPDATE`,
        [tenantId]
      );

      if (sub.rowCount === 0 || sub.rows[0].status !== 'active') {
        await client.query('ROLLBACK');
        return res
          .status(402)
          .json({ error: 'Assinatura inativa. Regularize o plano para cadastrar usuários.' });
      }

      const count = await client.query(
        'SELECT count(*)::int AS total FROM users WHERE tenant_id = $1',
        [tenantId]
      );

      if (count.rows[0].total >= sub.rows[0].max_users) {
        await client.query('ROLLBACK');
        return res
          .status(403)
          .json({ error: 'Limite de usuários do plano atingido.' });
      }

      // Role fixa no servidor; nunca vem do cliente
      const inserted = await client.query(
        `INSERT INTO users (tenant_id, name, email, password_hash, role)
         VALUES ($1, $2, $3, $4, 'member')
         RETURNING id, name, email, role, created_at`,
        [tenantId, name, email, passwordHash]
      );

      await client.query('COMMIT');

      const user = inserted.rows[0];
      return res.status(201).json({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        createdAt: user.created_at,
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});

      // violação do índice único (tenant_id, lower(email))
      if (err.code === '23505') {
        return res
          .status(409)
          .json({ error: 'Já existe um usuário com este e-mail nesta empresa.' });
      }
      return next(err);
    } finally {
      client.release();
    }
  }
);

module.exports = router;

/* ------------------------------------------------------------------ */
/* Exemplo de bootstrap                                                */
/* ------------------------------------------------------------------ */
// const app = express();
// app.use(express.json({ limit: '10kb' }));
// app.use(router);
// app.use((err, req, res, _next) => {
//   console.error(err);                       // nunca logar senha/hash
//   res.status(500).json({ error: 'Erro interno.' });
// });
// app.listen(3000);