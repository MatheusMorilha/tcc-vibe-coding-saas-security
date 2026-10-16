'use strict';

const { Pool } = require('pg');

// Credenciais via variáveis de ambiente (A02/A05): nunca no código.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  statement_timeout: 5000, // evita consultas longas (mitiga DoS)
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
});

module.exports = pool;

'use strict';

const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET ausente ou fraco (mínimo 32 caracteres).');
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }

  try {
    // Algoritmo fixado: evita ataques de "alg: none" / confusão de algoritmo (A02/A07)
    const payload = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    });

    if (!payload.sub || !payload.tenantId || !Array.isArray(payload.permissions)) {
      return res.status(401).json({ error: 'Token inválido.' });
    }

    // Identidade e tenant vêm SOMENTE do token assinado.
    req.user = {
      id: payload.sub,
      tenantId: payload.tenantId,
      permissions: payload.permissions,
    };
    return next();
  } catch (_err) {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
}

// Controle de acesso por permissão (A01)
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user || !req.user.permissions.includes(permission)) {
      return res.status(403).json({ error: 'Acesso negado.' });
    }
    return next();
  };
}

module.exports = { authenticate, requirePermission };

'use strict';

const { z } = require('zod');

// Validação por allowlist (A03): tipos, tamanhos e limites explícitos.
const listCustomersSchema = z
  .object({
    name: z.string().trim().min(1).max(100).optional(),
    page: z.coerce.number().int().min(1).max(10000).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  })
  .strict(); // rejeita parâmetros desconhecidos

function validateQuery(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.query);
    if (!result.success) {
      return res.status(400).json({ error: 'Parâmetros inválidos.' });
    }
    req.validatedQuery = result.data;
    return next();
  };
}

module.exports = { listCustomersSchema, validateQuery };

'use strict';

const express = require('express');
const pool = require('../db');
const { authenticate, requirePermission } = require('../middlewares/auth');
const { listCustomersSchema, validateQuery } = require('../middlewares/validate');

const router = express.Router();

// Escapa curingas do LIKE para que o usuário não force varreduras (%, _)
function escapeLike(value) {
  return value.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/**
 * GET /api/v1/customers?name=maria&page=1&limit=20
 */
router.get(
  '/',
  authenticate,
  requirePermission('customers:read'),
  validateQuery(listCustomersSchema),
  async (req, res) => {
    const { name, page, limit } = req.validatedQuery;
    const { tenantId } = req.user; // isolamento multilocatário
    const offset = (page - 1) * limit;

    // Consulta parametrizada (A03 – Injection). Nenhuma concatenação de entrada.
    const params = [tenantId];
    let where = 'WHERE tenant_id = $1 AND deleted_at IS NULL';

    if (name) {
      params.push(`%${escapeLike(name)}%`);
      where += ` AND name ILIKE $${params.length} ESCAPE '\\'`;
    }

    params.push(limit, offset);
    const limitIdx = params.length - 1;
    const offsetIdx = params.length;

    // Seleção explícita de colunas: evita expor campos sensíveis (A01/A04)
    const dataSql = `
      SELECT id, name, email, phone, created_at
      FROM customers
      ${where}
      ORDER BY name ASC, id ASC
      LIMIT $${limitIdx} OFFSET $${offsetIdx}`;

    const countSql = `SELECT COUNT(*)::int AS total FROM customers ${where}`;

    try {
      const [data, count] = await Promise.all([
        pool.query(dataSql, params),
        pool.query(countSql, params.slice(0, params.length - 2)),
      ]);

      // Log de auditoria sem dados pessoais do filtro (A09)
      req.log?.info({
        event: 'customers.list',
        userId: req.user.id,
        tenantId,
        returned: data.rowCount,
      });

      return res.json({
        data: data.rows,
        pagination: {
          page,
          limit,
          total: count.rows[0].total,
          totalPages: Math.ceil(count.rows[0].total / limit),
        },
      });
    } catch (err) {
      // Erro detalhado só no log interno; resposta genérica (A05/A09)
      req.log?.error({ err, event: 'customers.list.error' });
      return res.status(500).json({ error: 'Erro interno.' });
    }
  }
);

module.exports = router;

'use strict';

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const customersRouter = require('./routes/customers');

const app = express();

app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// Rate limiting contra abuso/enumeração (A04/A07)
app.use(
  '/api/',
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use('/api/v1/customers', customersRouter);

// 404 e handler global sem vazamento de stack trace (A05)
app.use((_req, res) => res.status(404).json({ error: 'Não encontrado.' }));
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Erro interno.' });
});

module.exports = app;