'use strict';

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { z } = require('zod');

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// Credenciais e segredos SEMPRE via variáveis de ambiente / secret manager
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
  max: 20,
  statement_timeout: 5000, // evita consultas abusivas
});

/* ------------------------------------------------------------------ */
/* Autenticação (A07) - o tenant vem do token assinado, NUNCA da request */
/* ------------------------------------------------------------------ */
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_PUBLIC_KEY, {
      algorithms: ['RS256'],            // fixa o algoritmo (evita "alg: none"/confusão de chaves)
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    });

    if (!payload.sub || !payload.tenant_id) {
      return res.status(401).json({ error: 'Não autenticado.' });
    }

    req.user = {
      id: String(payload.sub),
      tenantId: String(payload.tenant_id),
      permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
    };
    return next();
  } catch {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
}

/* ------------------------------------------------------------------ */
/* Autorização (A01) - controle de acesso por permissão                 */
/* ------------------------------------------------------------------ */
const requirePermission = (permission) => (req, res, next) => {
  if (!req.user.permissions.includes(permission)) {
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  return next();
};

/* ------------------------------------------------------------------ */
/* Plano de assinatura ativo - validado no servidor a cada requisição   */
/* ------------------------------------------------------------------ */
async function requireActiveSubscription(req, res, next) {
  try {
    const { rows } = await pool.query(
      `SELECT 1
         FROM subscriptions
        WHERE tenant_id = $1
          AND status = 'active'
          AND (expires_at IS NULL OR expires_at > now())
        LIMIT 1`,
      [req.user.tenantId]
    );
    if (rows.length === 0) {
      return res.status(402).json({ error: 'Assinatura inativa.' });
    }
    return next();
  } catch (err) {
    return next(err);
  }
}

/* ------------------------------------------------------------------ */
/* Rate limiting (A04/A05) - por usuário autenticado, com fallback IP   */
/* ------------------------------------------------------------------ */
const listLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.user ? `${req.user.tenantId}:${req.user.id}` : req.ip),
  message: { error: 'Muitas requisições. Tente novamente em instantes.' },
});

/* ------------------------------------------------------------------ */
/* Validação de entrada (A03) - allow-list, tipos e limites estritos    */
/* ------------------------------------------------------------------ */
const listQuerySchema = z
  .object({
    // z.string() rejeita arrays (?name=a&name=b) -> previne HTTP Parameter Pollution
    name: z.string().trim().min(1).max(100).optional(),
    page: z.coerce.number().int().min(1).max(10000).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  })
  .strict(); // rejeita parâmetros desconhecidos

// Escapa curingas do LIKE para o termo ser tratado como texto literal
const escapeLike = (value) => value.replace(/[\\%_]/g, '\\$&');

/* ------------------------------------------------------------------ */
/* Rota                                                                 */
/* ------------------------------------------------------------------ */
app.get(
  '/api/v1/customers',
  authenticate,
  listLimiter,
  requirePermission('customers:read'),
  requireActiveSubscription,
  async (req, res, next) => {
    const parsed = listQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Parâmetros inválidos.' });
    }

    const { name, page, limit } = parsed.data;
    const offset = (page - 1) * limit;

    // Query 100% parametrizada (A03). tenant_id é SEMPRE o primeiro filtro (A01).
    const params = [req.user.tenantId];
    let where = 'tenant_id = $1 AND deleted_at IS NULL';

    if (name) {
      params.push(`%${escapeLike(name)}%`);
      where += ` AND name ILIKE $${params.length} ESCAPE '\\'`;
    }

    params.push(limit + 1, offset); // busca 1 a mais para saber se há próxima página
    const sql = `
      SELECT id, name, email, phone, created_at
        FROM customers
       WHERE ${where}
       ORDER BY name ASC, id ASC
       LIMIT $${params.length - 1} OFFSET $${params.length}`;

    try {
      const { rows } = await pool.query(sql, params);
      const hasMore = rows.length > limit;

      res.set('Cache-Control', 'no-store'); // dados pessoais não devem ser cacheados
      return res.status(200).json({
        data: rows.slice(0, limit), // apenas colunas explícitas (sem exposição excessiva)
        pagination: { page, limit, hasMore },
      });
    } catch (err) {
      return next(err);
    }
  }
);

/* ------------------------------------------------------------------ */
/* Tratamento de erros e logging (A09/A05) - sem vazar detalhes         */
/* ------------------------------------------------------------------ */
app.use((err, req, res, _next) => {
  // Loga contexto útil para auditoria, sem dados pessoais nem o termo buscado
  console.error(
    JSON.stringify({
      level: 'error',
      msg: err.message,
      route: req.path,
      tenantId: req.user && req.user.tenantId,
      userId: req.user && req.user.id,
      at: new Date().toISOString(),
    })
  );
  res.status(500).json({ error: 'Erro interno.' });
});

module.exports = app;