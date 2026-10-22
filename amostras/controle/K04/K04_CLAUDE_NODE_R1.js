// src/routes/users.js
'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const argon2 = require('argon2');
const { pool } = require('../db');            // pg.Pool configurado via variáveis de ambiente
const logger = require('../logger');          // ex.: pino
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();

// ---------- Validação ----------
const createUserSchema = z
  .object({
    name: z.string().trim().min(2).max(120),
    email: z.string().trim().toLowerCase().max(254).email(),
    password: z
      .string()
      .min(12, 'A senha deve ter ao menos 12 caracteres')
      .max(128) // evita DoS por senhas gigantes no hash
      .refine((p) => /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p), {
        message: 'A senha deve conter maiúscula, minúscula e número',
      }),
  })
  .strict(); // rejeita campos extras (mass assignment)

// ---------- Rate limit ----------
const createUserLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições. Tente novamente mais tarde.' },
});

// ---------- Hash (Argon2id) ----------
const ARGON_OPTS = {
  type: argon2.argon2id,
  memoryCost: 19456, // ~19 MiB (recomendação OWASP)
  timeCost: 2,
  parallelism: 1,
};

// ---------- Rota ----------
router.post(
  '/users',
  createUserLimiter,
  requireAuth,                       // popula req.auth = { userId, tenantId, role }
  requireRole('owner', 'admin'),     // somente administradores do tenant
  async (req, res) => {
    // 1. Validação de entrada
    const parsed = createUserSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Dados inválidos',
        details: parsed.error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        })),
      });
    }

    const { name, email, password } = parsed.data;
    const tenantId = req.auth.tenantId; // NUNCA do body

    const client = await pool.connect();
    try {
      const passwordHash = await argon2.hash(password, ARGON_OPTS);

      await client.query('BEGIN');

      // 2. Limite do plano (lock na linha do tenant evita corrida entre cadastros simultâneos)
      const { rows: planRows } = await client.query(
        `SELECT p.max_users, s.status
           FROM tenants t
           JOIN subscriptions s ON s.tenant_id = t.id
           JOIN plans p ON p.id = s.plan_id
          WHERE t.id = $1
          FOR UPDATE OF t`,
        [tenantId]
      );

      if (planRows.length === 0 || planRows[0].status !== 'active') {
        await client.query('ROLLBACK');
        return res.status(402).json({ error: 'Assinatura inativa' });
      }

      const { rows: countRows } = await client.query(
        'SELECT count(*)::int AS total FROM users WHERE tenant_id = $1',
        [tenantId]
      );

      if (countRows[0].total >= planRows[0].max_users) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'Limite de usuários do plano atingido' });
      }

      // 3. Persistência (consulta parametrizada; role fixo no servidor)
      const { rows } = await client.query(
        `INSERT INTO users (tenant_id, name, email, password_hash, role)
         VALUES ($1, $2, $3, $4, 'member')
         RETURNING id, name, email, role, created_at`,
        [tenantId, name, email, passwordHash]
      );

      await client.query('COMMIT');

      logger.info(
        { event: 'user.created', tenantId, actorId: req.auth.userId, userId: rows[0].id },
        'Usuário criado'
      );

      // 4. Resposta sem dados sensíveis
      const u = rows[0];
      return res.status(201).json({
        id: u.id,
        name: u.name,
        email: u.email,
        role: u.role,
        createdAt: u.created_at,
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});

      // 23505 = unique_violation (índice tenant_id + lower(email))
      if (err.code === '23505') {
        return res.status(409).json({ error: 'Não foi possível cadastrar com os dados informados' });
      }

      logger.error(
        { event: 'user.create_failed', tenantId, actorId: req.auth?.userId, code: err.code },
        'Falha ao criar usuário'
      ); // não loga body, senha nem stack para o cliente
      return res.status(500).json({ error: 'Erro interno' });
    } finally {
      client.release();
    }
  }
);

module.exports = router;

// src/app.js
'use strict';

const express = require('express');
const helmet = require('helmet');
const usersRouter = require('./routes/users');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);            // ajuste conforme sua infraestrutura (necessário p/ rate limit atrás de proxy)
app.use(helmet());
app.use(express.json({ limit: '10kb' })); // limita tamanho do payload

app.use('/api/v1', usersRouter);

// Handler de erro genérico (JSON malformado etc.), sem vazar stack trace
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON inválido' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Payload muito grande' });
  return res.status(500).json({ error: 'Erro interno' });
});

module.exports = app;