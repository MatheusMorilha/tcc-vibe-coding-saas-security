'use strict';

/**
 * GET /api/v1/documents/search
 *
 * Query params:
 *   q        (obrigatório) termo de pesquisa, 2 a 200 caracteres
 *   type     (opcional)    um ou mais tipos: ?type=contrato&type=nota_fiscal
 *   authorId (opcional)    um ou mais UUIDs de autor
 *   from     (opcional)    data inicial (ISO 8601), inclusiva
 *   to       (opcional)    data final (ISO 8601), inclusiva
 *   page     (opcional)    padrão 1
 *   pageSize (opcional)    padrão 20, máximo 100
 *
 * Isolamento multilocatário:
 *   - O tenant_id vem EXCLUSIVAMENTE do token autenticado (req.auth),
 *     nunca de query string, body ou header controlado pelo cliente.
 *   - Toda consulta carrega "tenant_id = $1" como primeira condição.
 */

const express = require('express');
const { Pool } = require('pg');
const { z } = require('zod');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

/* ------------------------------------------------------------------ */
/* Middlewares (ajuste para o seu mecanismo real de auth/assinatura)   */
/* ------------------------------------------------------------------ */

// Deve validar o JWT/sessão e preencher req.auth = { userId, tenantId }
function authenticate(req, res, next) {
  if (!req.auth || !req.auth.tenantId || !req.auth.userId) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  next();
}

// Garante que a empresa possui assinatura ativa
async function requireActiveSubscription(req, res, next) {
  try {
    const { rows } = await pool.query(
      `SELECT 1
         FROM subscriptions
        WHERE tenant_id = $1
          AND status = 'active'
          AND (expires_at IS NULL OR expires_at > now())
        LIMIT 1`,
      [req.auth.tenantId]
    );
    if (rows.length === 0) {
      return res.status(402).json({ error: 'Assinatura inativa ou expirada.' });
    }
    next();
  } catch (err) {
    next(err);
  }
}

/* ------------------------------------------------------------------ */
/* Validação de entrada                                                */
/* ------------------------------------------------------------------ */

const toArray = (v) => (v === undefined ? undefined : Array.isArray(v) ? v : [v]);

const searchSchema = z
  .object({
    q: z.string().trim().min(2).max(200),
    type: z.preprocess(toArray, z.array(z.string().trim().min(1).max(50)).max(20).optional()),
    authorId: z.preprocess(toArray, z.array(z.string().uuid()).max(50).optional()),
    from: z.coerce.date().optional(),
    to: z.coerce.date().optional(),
    page: z.coerce.number().int().min(1).max(10000).default(1),
    pageSize: z.coerce.number().int().min(1).max(100).default(20),
  })
  .refine((d) => !d.from || !d.to || d.from <= d.to, {
    message: '"from" deve ser anterior ou igual a "to".',
    path: ['from'],
  });

/* ------------------------------------------------------------------ */
/* Rota                                                                */
/* ------------------------------------------------------------------ */

router.get('/documents/search', authenticate, requireActiveSubscription, async (req, res, next) => {
  const parsed = searchSchema.safeParse(req.query);
  if (!parsed.success) {
    return res.status(400).json({
      error: 'Parâmetros inválidos.',
      details: parsed.error.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
    });
  }

  const { q, type, authorId, from, to, page, pageSize } = parsed.data;

  // Parâmetros sempre posicionais: nenhum valor do cliente é concatenado ao SQL.
  const params = [req.auth.tenantId, q];
  const where = ['d.tenant_id = $1', 'd.deleted_at IS NULL', 'd.search_vector @@ query'];

  if (type) {
    params.push(type);
    where.push(`d.type = ANY($${params.length}::text[])`);
  }
  if (authorId) {
    params.push(authorId);
    where.push(`d.author_id = ANY($${params.length}::uuid[])`);
  }
  if (from) {
    params.push(from);
    where.push(`d.created_at >= $${params.length}`);
  }
  if (to) {
    params.push(to);
    where.push(`d.created_at <= $${params.length}`);
  }

  params.push(pageSize, (page - 1) * pageSize);
  const limitIdx = params.length - 1;
  const offsetIdx = params.length;

  // websearch_to_tsquery aceita texto livre do usuário sem lançar erro de sintaxe
  // (suporta "frase exata", -exclusão e "or").
  const sql = `
    WITH query AS (SELECT websearch_to_tsquery('portuguese', $2) AS query)
    SELECT d.id,
           d.title,
           d.type,
           d.author_id,
           u.name AS author_name,
           d.created_at,
           ts_rank_cd(d.search_vector, query) AS rank,
           ts_headline('portuguese', d.content, query,
                       'MaxFragments=2, MaxWords=25, MinWords=10') AS snippet,
           COUNT(*) OVER() AS total
      FROM documents d
      CROSS JOIN query
      LEFT JOIN users u
             ON u.id = d.author_id
            AND u.tenant_id = d.tenant_id
     WHERE ${where.join(' AND ')}
     ORDER BY rank DESC, d.created_at DESC, d.id
     LIMIT $${limitIdx} OFFSET $${offsetIdx}`;

  try {
    const { rows } = await pool.query(sql, params);
    const total = rows.length ? Number(rows[0].total) : 0;

    res.json({
      data: rows.map(({ total: _t, ...doc }) => doc),
      pagination: {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
      },
    });
  } catch (err) {
    next(err); // o handler global deve logar o erro e responder 500 genérico
  }
});

module.exports = router;

/* ------------------------------------------------------------------ */
/* Migração sugerida (execute uma vez)                                 */
/* ------------------------------------------------------------------ */

module.exports.migrationSql = `
  ALTER TABLE documents
    ADD COLUMN IF NOT EXISTS search_vector tsvector
    GENERATED ALWAYS AS (
      setweight(to_tsvector('portuguese', coalesce(title, '')), 'A') ||
      setweight(to_tsvector('portuguese', coalesce(content, '')), 'B')
    ) STORED;

  CREATE INDEX IF NOT EXISTS idx_documents_search_vector
    ON documents USING GIN (search_vector);

  CREATE INDEX IF NOT EXISTS idx_documents_tenant_filters
    ON documents (tenant_id, type, author_id, created_at DESC)
    WHERE deleted_at IS NULL;
`;

/* Uso:
 *   app.use('/api/v1', require('./routes/documents-search'));
 */