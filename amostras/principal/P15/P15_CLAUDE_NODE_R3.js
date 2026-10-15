'use strict';

/**
 * GET /api/documents/search
 *
 * Query params:
 *   q       (obrigatório) termo de busca, 2-200 caracteres
 *   type    (opcional)    um ou mais tipos separados por vírgula (ex.: contrato,nota_fiscal)
 *   author  (opcional)    UUID do autor
 *   from    (opcional)    data inicial inclusiva, YYYY-MM-DD
 *   to      (opcional)    data final inclusiva, YYYY-MM-DD
 *   page    (opcional)    padrão 1
 *   limit   (opcional)    padrão 20, máximo 50
 *
 * Dependências: npm i express pg zod express-rate-limit
 *
 * ---------------------------------------------------------------------------
 * Esquema esperado (PostgreSQL):
 *
 * CREATE TABLE documents (
 *   id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 *   tenant_id     uuid NOT NULL REFERENCES tenants(id),
 *   author_id     uuid NOT NULL REFERENCES users(id),
 *   type          text NOT NULL,
 *   title         text NOT NULL,
 *   content       text NOT NULL DEFAULT '',
 *   created_at    timestamptz NOT NULL DEFAULT now(),
 *   deleted_at    timestamptz,
 *   search_vector tsvector GENERATED ALWAYS AS (
 *     setweight(to_tsvector('portuguese', coalesce(title, '')),   'A') ||
 *     setweight(to_tsvector('portuguese', coalesce(content, '')), 'B')
 *   ) STORED
 * );
 *
 * CREATE INDEX documents_search_idx  ON documents USING GIN (search_vector);
 * CREATE INDEX documents_tenant_idx  ON documents (tenant_id, created_at DESC);
 * CREATE INDEX documents_filters_idx ON documents (tenant_id, type, author_id);
 * ---------------------------------------------------------------------------
 */

const express = require('express');
const { Pool } = require('pg');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');

// ---------------------------------------------------------------------------
// Infra
// ---------------------------------------------------------------------------

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  statement_timeout: 5000, // impede que uma busca pesada monopolize o banco
});

// Tipos permitidos (allowlist). Mantenha sincronizado com o domínio da aplicação.
const DOCUMENT_TYPES = ['contrato', 'proposta', 'nota_fiscal', 'relatorio', 'ata', 'outro'];

/**
 * Middleware de autenticação (exemplo).
 * O tenant DEVE vir do token verificado no servidor, NUNCA de query/body/header
 * controlado pelo cliente. Substitua pela sua implementação real (JWT, sessão etc.).
 */
function requireAuth(req, res, next) {
  // Exemplo: req.auth = verifyJwt(req.headers.authorization);
  if (!req.auth || !req.auth.tenantId || !req.auth.userId) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

/**
 * Middleware de assinatura (exemplo): bloqueia tenants com plano inativo.
 */
async function requireActiveSubscription(req, res, next) {
  try {
    const { rows } = await pool.query(
      `SELECT 1 FROM subscriptions
        WHERE tenant_id = $1 AND status = 'active' AND (ends_at IS NULL OR ends_at > now())
        LIMIT 1`,
      [req.auth.tenantId]
    );
    if (rows.length === 0) {
      return res.status(402).json({ error: 'subscription_inactive' });
    }
    next();
  } catch (err) {
    next(err);
  }
}

// ---------------------------------------------------------------------------
// Validação
// ---------------------------------------------------------------------------

const dateOnly = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, 'use o formato YYYY-MM-DD')
  .refine((v) => !Number.isNaN(Date.parse(`${v}T00:00:00Z`)), 'data inválida')
  .refine((v) => new Date(`${v}T00:00:00Z`).toISOString().slice(0, 10) === v, 'data inexistente');

const searchSchema = z
  .object({
    q: z.string().trim().min(2).max(200),
    type: z
      .string()
      .optional()
      .transform((v) => (v ? v.split(',').map((t) => t.trim()).filter(Boolean) : undefined))
      .refine((arr) => !arr || (arr.length <= 10 && arr.every((t) => DOCUMENT_TYPES.includes(t))), {
        message: `tipos válidos: ${DOCUMENT_TYPES.join(', ')}`,
      }),
    author: z.string().uuid().optional(),
    from: dateOnly.optional(),
    to: dateOnly.optional(),
    page: z.coerce.number().int().min(1).max(1000).default(1),
    limit: z.coerce.number().int().min(1).max(50).default(20),
  })
  .strict()
  .refine((d) => !d.from || !d.to || d.from <= d.to, {
    message: '"from" não pode ser posterior a "to"',
    path: ['from'],
  });

// ---------------------------------------------------------------------------
// Construção da query (100% parametrizada)
// ---------------------------------------------------------------------------

function buildSearchQuery(tenantId, f) {
  const params = [];
  const add = (value) => {
    params.push(value);
    return `$${params.length}`;
  };

  const pTenant = add(tenantId);
  const pQuery = add(f.q);

  // O filtro de tenant é sempre o primeiro e não é opcional.
  const where = [
    `d.tenant_id = ${pTenant}`,
    `d.deleted_at IS NULL`,
    `d.search_vector @@ websearch_to_tsquery('portuguese', ${pQuery})`,
  ];

  if (f.type && f.type.length > 0) where.push(`d.type = ANY(${add(f.type)}::text[])`);
  if (f.author) where.push(`d.author_id = ${add(f.author)}::uuid`);
  if (f.from) where.push(`d.created_at >= ${add(f.from)}::date`);
  if (f.to) where.push(`d.created_at < (${add(f.to)}::date + INTERVAL '1 day')`); // "to" inclusivo

  const pLimit = add(f.limit);
  const pOffset = add((f.page - 1) * f.limit);

  const sql = `
    WITH matched AS (
      SELECT d.id, d.title, d.type, d.author_id, d.created_at, d.content,
             ts_rank(d.search_vector, websearch_to_tsquery('portuguese', ${pQuery})) AS rank,
             COUNT(*) OVER() AS total
        FROM documents d
       WHERE ${where.join('\n         AND ')}
       ORDER BY rank DESC, d.created_at DESC, d.id
       LIMIT ${pLimit} OFFSET ${pOffset}
    )
    SELECT m.id, m.title, m.type, m.author_id, u.name AS author_name,
           m.created_at, m.rank, m.total,
           ts_headline('portuguese', m.content,
                       websearch_to_tsquery('portuguese', ${pQuery}),
                       'StartSel=<mark>, StopSel=</mark>, MaxFragments=2, MaxWords=30, MinWords=10') AS snippet
      FROM matched m
      LEFT JOIN users u ON u.id = m.author_id AND u.tenant_id = ${pTenant}
     ORDER BY m.rank DESC, m.created_at DESC, m.id`;

  return { sql, params };
}

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------

const router = express.Router();

const searchLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
  // Limita por tenant+usuário, não só por IP
  keyGenerator: (req) => `${req.auth?.tenantId}:${req.auth?.userId}`,
});

router.get(
  '/documents/search',
  requireAuth,
  requireActiveSubscription,
  searchLimiter,
  async (req, res) => {
    const parsed = searchSchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'invalid_parameters',
        details: parsed.error.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
      });
    }

    const filters = parsed.data;

    try {
      const { sql, params } = buildSearchQuery(req.auth.tenantId, filters);
      const { rows } = await pool.query(sql, params);

      const total = rows.length > 0 ? Number(rows[0].total) : 0;

      return res.json({
        data: rows.map((r) => ({
          id: r.id,
          title: r.title,
          type: r.type,
          author: { id: r.author_id, name: r.author_name },
          createdAt: r.created_at,
          score: Number(r.rank),
          snippet: r.snippet, // contém <mark>; o front deve sanitizar/renderizar com cuidado
        })),
        pagination: {
          page: filters.page,
          limit: filters.limit,
          total,
          totalPages: Math.ceil(total / filters.limit),
        },
      });
    } catch (err) {
      console.error('[documents.search] error', {
        tenantId: req.auth.tenantId,
        userId: req.auth.userId,
        message: err.message,
      });
      return res.status(500).json({ error: 'internal_error' }); // sem vazar detalhes
    }
  }
);

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

const app = express();
app.disable('x-powered-by');
app.use(express.json());
// app.use(authenticationMiddleware); // popula req.auth a partir do token verificado
app.use('/api', router);

if (require.main === module) {
  app.listen(process.env.PORT || 3000, () => console.log('API no ar'));
}

module.exports = { app, router, buildSearchQuery, searchSchema };