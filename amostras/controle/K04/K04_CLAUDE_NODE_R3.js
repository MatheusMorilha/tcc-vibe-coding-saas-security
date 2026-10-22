// src/db.js
import pg from 'pg';

export const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL, // credenciais fora do código
  max: 10,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
});

// src/middleware/auth.js
import jwt from 'jsonwebtoken';

// Autentica e injeta { userId, tenantId, role } vindos do TOKEN, não do cliente.
export function authenticate(req, res, next) {
  const header = req.headers.authorization ?? '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],          // fixa o algoritmo (evita alg=none / confusão)
      issuer: 'saas-api',
    });
    req.auth = { userId: payload.sub, tenantId: payload.tid, role: payload.role };
    next();
  } catch {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
}

export function requireRole(...roles) {
  return (req, res, next) =>
    roles.includes(req.auth?.role)
      ? next()
      : res.status(403).json({ error: 'Acesso negado.' });
}

// src/routes/users.js
import { Router } from 'express';
import { z } from 'zod';
import argon2 from 'argon2';
import rateLimit from 'express-rate-limit';
import { pool } from '../db.js';
import { authenticate, requireRole } from '../middleware/auth.js';

const router = Router();

const createUserSchema = z
  .object({
    name: z.string().trim().min(2).max(100),
    email: z.string().trim().toLowerCase().email().max(254),
    password: z
      .string()
      .min(12, 'A senha deve ter no mínimo 12 caracteres.')
      .max(128), // limita custo de hashing (DoS)
  })
  .strict(); // rejeita campos extras: tenant_id, role, id, etc.

const createUserLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456, // ~19 MiB (recomendação OWASP)
  timeCost: 2,
  parallelism: 1,
};

router.post(
  '/users',
  createUserLimiter,
  authenticate,
  requireRole('admin'),
  async (req, res, next) => {
    // 1. Validação de entrada
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
    const { tenantId } = req.auth; // origem confiável

    try {
      // 2. Hash fora da transação, para não segurar lock durante operação cara
      const passwordHash = await argon2.hash(password, ARGON2_OPTIONS);

      const client = await pool.connect();
      try {
        await client.query('BEGIN');

        // 3. Trava a linha do tenant e valida plano/limite de usuários
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
          'SELECT count(*)::int AS total FROM users WHERE tenant_id = $1',
          [tenantId]
        );
        if (countRows[0].total >= tenant.max_users) {
          await client.query('ROLLBACK');
          return res
            .status(403)
            .json({ error: 'Limite de usuários do plano atingido.' });
        }

        // 4. Persistência (parametrizada). Role fixa; sem mass assignment.
        const { rows } = await client.query(
          `INSERT INTO users (tenant_id, name, email, password_hash, role)
           VALUES ($1, $2, $3, $4, 'member')
           RETURNING id, name, email, role, created_at`,
          [tenantId, name, email, passwordHash]
        );

        await client.query('COMMIT');

        // 5. Resposta sem dados sensíveis
        return res
          .status(201)
          .location(`/users/${rows[0].id}`)
          .json({
            id: rows[0].id,
            name: rows[0].name,
            email: rows[0].email,
            role: rows[0].role,
            createdAt: rows[0].created_at,
          });
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        if (err.code === '23505') {
          // violação do índice único (tenant_id, lower(email))
          return res
            .status(409)
            .json({ error: 'E-mail já cadastrado nesta empresa.' });
        }
        throw err;
      } finally {
        client.release();
      }
    } catch (err) {
      next(err);
    }
  }
);

export default router;
