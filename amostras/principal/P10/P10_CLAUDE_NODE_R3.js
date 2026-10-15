'use strict';

/**
 * Rota: POST /api/users
 *
 * Pré-requisitos (já existentes na aplicação):
 *  - requireAuth: valida o JWT/sessão e popula req.auth = { userId, tenantId, role }
 *  - requireRole: restringe a rota a perfis autorizados
 *
 * Esquema SQL esperado (PostgreSQL):
 *
 *   CREATE TABLE users (
 *     id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 *     tenant_id      UUID NOT NULL REFERENCES tenants(id),
 *     name           TEXT NOT NULL,
 *     email          TEXT NOT NULL,
 *     password_hash  TEXT NOT NULL,
 *     role           TEXT NOT NULL DEFAULT 'member',
 *     created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
 *     deleted_at     TIMESTAMPTZ
 *   );
 *   -- E-mail único dentro de cada empresa (não globalmente)
 *   CREATE UNIQUE INDEX users_tenant_email_uq ON users (tenant_id, lower(email));
 *   CREATE INDEX users_tenant_idx ON users (tenant_id);
 */

const express = require('express');
const { Pool } = require('pg');
const argon2 = require('argon2');
const { z } = require('zod');
const { requireAuth, requireRole } = require('../middlewares/auth');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

// .strict() rejeita campos extras (ex.: tenantId, role) -> evita mass assignment
const createUserSchema = z
  .object({
    name: z.string().trim().min(2).max(120),
    email: z.string().trim().toLowerCase().email().max(254),
    password: z.string().min(10).max(128),
  })
  .strict();

router.post(
  '/users',
  requireAuth,
  requireRole('owner', 'admin'),
  async (req, res, next) => {
    const parsed = createUserSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'validation_error',
        details: parsed.error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        })),
      });
    }

    const { name, email, password } = parsed.data;
    const tenantId = req.auth.tenantId; // vem da sessão, NUNCA do body

    let client;
    try {
      // Hash feito antes de abrir a transação (operação custosa)
      const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

      client = await pool.connect();
      await client.query('BEGIN');

      // Trava a linha do tenant para evitar corrida no limite de usuários do plano
      const { rows } = await client.query(
        `SELECT s.status, p.max_users
           FROM tenants t
           JOIN subscriptions s ON s.tenant_id = t.id
           JOIN plans p         ON p.id = s.plan_id
          WHERE t.id = $1
          FOR UPDATE OF t`,
        [tenantId]
      );
      const plan = rows[0];

      if (!plan || !['active', 'trialing'].includes(plan.status)) {
        await client.query('ROLLBACK');
        return res.status(402).json({ error: 'subscription_inactive' });
      }

      if (plan.max_users !== null) {
        const { rows: cnt } = await client.query(
          `SELECT count(*)::int AS total
             FROM users
            WHERE tenant_id = $1 AND deleted_at IS NULL`,
          [tenantId]
        );
        if (cnt[0].total >= plan.max_users) {
          await client.query('ROLLBACK');
          return res.status(403).json({ error: 'plan_user_limit_reached' });
        }
      }

      const { rows: created } = await client.query(
        `INSERT INTO users (tenant_id, name, email, password_hash, role)
         VALUES ($1, $2, $3, $4, 'member')
         RETURNING id, name, email, role, created_at AS "createdAt"`,
        [tenantId, name, email, passwordHash]
      );

      await client.query('COMMIT');

      // Nunca retorna password_hash nem tenant_id interno desnecessário
      return res.status(201).json(created[0]);
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      if (err.code === '23505') {
        return res.status(409).json({ error: 'email_already_registered' });
      }
      return next(err);
    } finally {
      if (client) client.release();
    }
  }
);

module.exports = router;

/* Uso no app principal:
 *
 *   const app = express();
 *   app.use(express.json({ limit: '10kb' }));
 *   app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }), require('./routes/users'));
 */