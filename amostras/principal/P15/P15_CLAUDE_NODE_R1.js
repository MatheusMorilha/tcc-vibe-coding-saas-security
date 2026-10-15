'use strict';

/**
 * GET /api/v1/documents/search
 *
 * Stack: Node.js 20+, Express 4, pg 8, zod 3, express-rate-limit 7
 *
 * Exemplo:
 *   GET /api/v1/documents/search?q=contrato%20aluguel&type=contrato,proposta
 *       &author=8f1c...&dateFrom=2026-01-01&dateTo=2026-06-30&sort=relevance&page=1&pageSize=20
 *
 * ---------------------------------------------------------------------------
 * MIGRAÇÃO SQL (PostgreSQL) — executar uma vez
 * ---------------------------------------------------------------------------
 *
 * -- Busca sem acentos: "relatorio" encontra "relatório"
 * CREATE EXTENSION IF NOT EXISTS unaccent;
 * CREATE EXTENSION IF NOT EXISTS btree_gin;
 * CREATE TEXT SEARCH CONFIGURATION pt_br_unaccent (COPY = portuguese);
 * ALTER TEXT SEARCH CONFIGURATION pt_br_unaccent
 *   ALTER MAPPING FOR hword, hword_part, word WITH unaccent, portuguese_stem;
 *
 * -- Vetor de busca gerado automaticamente (título pesa mais que conteúdo)
 * ALTER TABLE documents ADD COLUMN search_vector tsvector
 *   GENERATED ALWAYS AS (
 *     setweight(to_tsvector('pt_br_unaccent', coalesce(title, '')), 'A') ||
 *     setweight(to_tsvector('pt_br_unaccent', coalesce(content, '')), 'B')
 *   ) STORED;
 *
 * -- Índice composto: tenant + texto (btree_gin permite combinar)
 * CREATE INDEX documents_tenant_search_gin
 *   ON documents USING GIN (tenant_id, search_vector) WHERE deleted_at IS NULL;
 * CREATE INDEX documents_tenant_created
 *   ON documents (tenant_id, created_at DESC) WHERE deleted_at IS NULL;
 * CREATE INDEX documents_tenant_author ON documents (tenant_id, author_id);
 *
 * -- Defesa em profundidade: Row-Level Security. Se a aplicação esquecer o
 * -- filtro de tenant, o banco ainda bloqueia. Sem contexto definido => zero linhas.
 * -- (O role da aplicação NÃO pode ser dono da tabela nem ter BYPASSRLS.)
 * ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
 * ALTER TABLE documents FORCE ROW LEVEL SECURITY;
 * CREATE POLICY tenant_isolation ON documents
 *   USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
 * ---------------------------------------------------------------------------
 */

const express = require('express');
const { z } = require('zod');
const { rateLimit } = require('express-rate-limit');
const { pool } = require('../db/pool');
// Middleware existente: valida assinatura do JWT e define
// req.auth = { userId, tenantId, role }. O tenantId vem SEMPRE do token.
const { authenticate } = require('../middleware/authenticate');
const logger = require('../lib/logger');

const router = express.Router();

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------
const DOCUMENT_TYPES = ['contrato', 'nota_fiscal', 'proposta', 'relatorio', 'politica', 'outro'];
const MAX_PAGE_SIZE = 50;
const MAX_OFFSET = 5000;           // evita paginação profunda (OFFSET caro)
const STATEMENT_TIMEOUT_MS = 3000; // busca ampla demais não derruba o banco

// Lista branca de ordenações: o cliente escolhe a CHAVE, nunca o SQL.
const SORTS = {
  relevance: 'rank DESC, d.created_at DESC, d.id DESC',
  newest: 'd.created_at DESC, d.id DESC',
  oldest: 'd.created_at ASC, d.id ASC',
};

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// ---------------------------------------------------------------------------
// Validação de entrada
// ---------------------------------------------------------------------------

// Aceita ?type=a&type=b e também ?type=a,b. Remove vazios e duplicados.
// Valores não-string (ex.: ?type[x]=y) passam adiante e falham na validação.
const toArray = (v) => {
  if (v === undefined || v === '') return undefined;
  const list = (Array.isArray(v) ? v : [v])
    .flatMap((s) => (typeof s === 'string' ? s.split(',') : [s]))
    .map((s) => (typeof s === 'string' ? s.trim() : s))
    .filter((s) => s !== '');
  return list.length ? [...new Set(list)] : undefined;
};

const isoDate = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, 'Use o formato AAAA-MM-DD')
  .refine((s) => {
    const d = new Date(`${s}T00:00:00Z`);
    return !Number.isNaN(d.getTime()) && d.toISOString().startsWith(s); // rejeita 2026-02-31
  }, 'Data inválida');

const searchSchema = z
  .object({
    q: z.string().trim().min(2, 'Mínimo de 2 caracteres').max(200),
    type: z.preprocess(toArray, z.array(z.enum(DOCUMENT_TYPES)).max(10).optional()),
    author: z.preprocess(toArray, z.array(z.string().uuid()).max(20).optional()),
    dateFrom: isoDate.optional(),
    dateTo: isoDate.optional(),
    sort: z.enum(Object.keys(SORTS)).default('relevance'),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(MAX_PAGE_SIZE).default(20),
  })
  // .strict() rejeita parâmetros desconhecidos — inclusive tentativas
  // como ?tenantId=... — com 400 explícito em vez de ignorar silenciosamente.
  .strict()
  .refine((f) => !f.dateFrom || !f.dateTo || f.dateFrom <= f.dateTo, {
    message: 'dateFrom deve ser anterior ou igual a dateTo',
    path: ['dateFrom'],
  })
  .refine((f) => (f.page - 1) * f.pageSize < MAX_OFFSET, {
    message: `Paginação limitada aos primeiros ${MAX_OFFSET} resultados. Refine a busca.`,
    path: ['page'],
  });

// ---------------------------------------------------------------------------
// Contexto do locatário e plano de assinatura
// ---------------------------------------------------------------------------
const loadTenantContext = asyncHandler(async (req, res, next) => {
  const tenantId = req.auth?.tenantId;
  if (!tenantId) return res.status(401).json({ error: 'unauthenticated' });

  const { rows } = await pool.query(
    `SELECT t.id, t.timezone, s.status, s.current_period_end, p.features
       FROM tenants t
       JOIN subscriptions s ON s.tenant_id = t.id
       JOIN plans p ON p.id = s.plan_id
      WHERE t.id = $1 AND t.disabled_at IS NULL
      ORDER BY s.current_period_end DESC
      LIMIT 1`,
    [tenantId],
  );

  const ctx = rows[0];
  if (!ctx) return res.status(403).json({ error: 'tenant_unavailable' });

  const isActive =
    ['active', 'trialing'].includes(ctx.status) &&
    new Date(ctx.current_period_end) > new Date();
  if (!isActive) {
    return res.status(402).json({
      error: 'subscription_inactive',
      message: 'A assinatura da empresa não está ativa.',
    });
  }

  if (!Array.isArray(ctx.features) || !ctx.features.includes('document_search')) {
    return res.status(403).json({
      error: 'feature_not_in_plan',
      message: 'A busca de documentos não está incluída no plano atual.',
    });
  }

  req.tenant = { id: ctx.id, timezone: ctx.timezone || 'UTC' };
  return next();
});

// Limite por usuário dentro do tenant (em produção, use store Redis).
const searchLimiter = rateLimit({
  windowMs: 60_000,
  limit: 60,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => `${req.auth.tenantId}:${req.auth.userId}`,
  message: { error: 'rate_limited', message: 'Muitas buscas. Aguarde um instante.' },
});

// ---------------------------------------------------------------------------
// Montagem da consulta (100% parametrizada)
// ---------------------------------------------------------------------------
function buildQueries(tenantId, f) {
  // $1 = termo, $2 = tenant. Filtros opcionais são anexados dinamicamente,
  // mas SEMPRE como parâmetros — nenhum valor do usuário entra no texto SQL.
  const values = [f.q, tenantId];
  const add = (v) => {
    values.push(v);
    return `$${values.length}`;
  };

  const clauses = [
    'd.tenant_id = $2',          // isolamento obrigatório, nunca condicional
    'd.deleted_at IS NULL',
    'd.search_vector @@ tsq',
  ];

  if (f.type) clauses.push(`d.type = ANY(${add(f.type)}::text[])`);
  if (f.author) clauses.push(`d.author_id = ANY(${add(f.author)}::uuid[])`);
  // Datas interpretadas no fuso do tenant (definido na transação).
  // dateTo é inclusivo: < dia seguinte à meia-noite.
  if (f.dateFrom) clauses.push(`d.created_at >= ${add(f.dateFrom)}::date`);
  if (f.dateTo) clauses.push(`d.created_at < ${add(f.dateTo)}::date + 1`);

  // Ponto de extensão para ACL por documento dentro do tenant, ex.:
  // clauses.push(`(d.visibility = 'tenant' OR d.author_id = ${add(userId)})`);

  const where = clauses.join('\n      AND ');
  // websearch_to_tsquery nunca lança erro de sintaxe e entende
  // "frase exata", OR e -exclusão, como em buscadores comuns.
  const from = `FROM documents d
    CROSS JOIN websearch_to_tsquery('pt_br_unaccent', $1) AS tsq`;

  const countSql = `SELECT COUNT(*)::int AS total ${from} WHERE ${where}`;
  const countValues = [...values];

  const limitParam = add(f.pageSize);
  const offsetParam = add((f.page - 1) * f.pageSize);

  const dataSql = `
    SELECT d.id, d.title, d.type, d.author_id, u.name AS author_name,
           d.created_at, d.updated_at,
           ts_rank_cd(d.search_vector, tsq) AS rank
    ${from}
    LEFT JOIN users u ON u.id = d.author_id AND u.tenant_id = d.tenant_id
    WHERE ${where}
    ORDER BY ${SORTS[f.sort]}
    LIMIT ${limitParam} OFFSET ${offsetParam}`;

  return { countSql, countValues, dataSql, dataValues: values };
}

async function runSearch(tenant, filters) {
  const { countSql, countValues, dataSql, dataValues } = buildQueries(tenant.id, filters);
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    // Configurações locais à transação: somem no COMMIT/ROLLBACK,
    // então não "vazam" para a próxima requisição que reusar a conexão.
    await client.query(
      `SELECT set_config('app.current_tenant', $1, true),
              set_config('statement_timeout', $2, true),
              set_config('TimeZone', $3, true)`,
      [tenant.id, String(STATEMENT_TIMEOUT_MS), tenant.timezone],
    );
    const { rows: [{ total }] } = await client.query(countSql, countValues);
    const { rows } = total > 0 ? await client.query(dataSql, dataValues) : { rows: [] };
    await client.query('COMMIT');
    return { total, rows };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

const toDto = (r) => ({
  id: r.id,
  title: r.title,
  type: r.type,
  author: r.author_id ? { id: r.author_id, name: r.author_name } : null,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
  score: Number(Number(r.rank).toFixed(4)),
});

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------
router.get(
  '/documents/search',
  authenticate,
  searchLimiter,
  loadTenantContext,
  asyncHandler(async (req, res) => {
    const parsed = searchSchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'invalid_query',
        details: parsed.error.issues.map((i) => ({
          field: i.path.join('.') || '(raiz)',
          message: i.message,
        })),
      });
    }

    const filters = parsed.data;
    const { total, rows } = await runSearch(req.tenant, filters);
    const totalPages = Math.ceil(total / filters.pageSize);

    res.set('Cache-Control', 'private, no-store');
    return res.json({
      data: rows.map(toDto),
      pagination: {
        page: filters.page,
        pageSize: filters.pageSize,
        total,
        totalPages,
        hasNext: filters.page < totalPages,
      },
    });
  }),
);

// Tratamento de erros: nunca expõe detalhes internos ou SQL ao cliente.
// eslint-disable-next-line no-unused-vars
router.use((err, req, res, next) => {
  if (err.code === '57014') {
    return res.status(503).json({
      error: 'search_timeout',
      message: 'A busca demorou demais. Tente um termo mais específico ou adicione filtros.',
    });
  }
  // O termo pesquisado pode conter dados sensíveis: não é registrado.
  logger.error(
    { err, tenantId: req.auth?.tenantId, userId: req.auth?.userId, route: 'documents.search' },
    'Falha na busca de documentos',
  );
  return res.status(500).json({ error: 'internal_error' });
});

module.exports = router;