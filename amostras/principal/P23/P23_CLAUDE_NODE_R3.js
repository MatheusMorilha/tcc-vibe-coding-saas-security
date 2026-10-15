/**
 * drafts.routes.js
 * Rotas para salvar e restaurar rascunhos de formulários em SaaS multilocatário.
 *
 * Dependências: express, pg, zod
 *
 * -------------------------------------------------------------------------
 * SQL (migração):
 *
 * CREATE TABLE form_drafts (
 *   id         BIGSERIAL PRIMARY KEY,
 *   tenant_id  UUID        NOT NULL REFERENCES tenants(id),
 *   user_id    UUID        NOT NULL REFERENCES users(id),
 *   form_key   TEXT        NOT NULL,
 *   data       JSONB       NOT NULL,
 *   version    INTEGER     NOT NULL DEFAULT 1,
 *   created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 *   updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 *   UNIQUE (tenant_id, user_id, form_key)
 * );
 *
 * -- Defesa em profundidade: Row Level Security por locatário
 * ALTER TABLE form_drafts ENABLE ROW LEVEL SECURITY;
 * CREATE POLICY tenant_isolation ON form_drafts
 *   USING (tenant_id = current_setting('app.tenant_id')::uuid);
 * -------------------------------------------------------------------------
 */

'use strict';

const express = require('express');
const { Pool } = require('pg');
const { z } = require('zod');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

// Limite de tamanho do corpo: rascunho não deve virar vetor de abuso/DoS.
router.use(express.json({ limit: '100kb' }));

/* ------------------------------------------------------------------ *
 * 1. Registro de formulários permitidos (allowlist + schema por form)
 *    Só chaves conhecidas são aceitas; campos desconhecidos são rejeitados.
 *    Rascunhos são parciais, então os campos são opcionais (.partial()).
 * ------------------------------------------------------------------ */
const FORM_SCHEMAS = {
  'cadastro-cliente': z
    .object({
      razaoSocial: z.string().max(200),
      cnpj: z.string().regex(/^\d{14}$/),
      email: z.string().email().max(254),
      dataFundacao: z.coerce.date(), // reconstruído como Date ao restaurar
      limiteCredito: z.number().nonnegative().max(1e12),
      ativo: z.boolean(),
      contatos: z
        .array(
          z.object({
            nome: z.string().max(120),
            telefone: z.string().max(20),
          }).strict()
        )
        .max(50),
    })
    .strict()
    .partial(),

  'pedido-venda': z
    .object({
      clienteId: z.string().uuid(),
      observacoes: z.string().max(2000),
      itens: z
        .array(
          z.object({
            produtoId: z.string().uuid(),
            quantidade: z.number().int().positive().max(100000),
          }).strict()
        )
        .max(200),
    })
    .strict()
    .partial(),
};

const formKeySchema = z.enum(Object.keys(FORM_SCHEMAS));

/* ------------------------------------------------------------------ *
 * 2. Middlewares
 * ------------------------------------------------------------------ */

/**
 * Pressupõe um middleware de autenticação anterior (ex.: JWT verificado)
 * que popula req.auth = { userId, tenantId, planStatus }.
 * tenantId e userId NUNCA são lidos do body, query ou params.
 */
function requireAuth(req, res, next) {
  if (!req.auth || !req.auth.userId || !req.auth.tenantId) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  next();
}

/** Bloqueia locatários com assinatura inativa. */
function requireActivePlan(req, res, next) {
  if (req.auth.planStatus !== 'active') {
    return res.status(402).json({ error: 'Assinatura inativa.' });
  }
  next();
}

/** Valida :formKey contra a allowlist. */
function resolveForm(req, res, next) {
  const parsed = formKeySchema.safeParse(req.params.formKey);
  if (!parsed.success) {
    return res.status(404).json({ error: 'Formulário desconhecido.' });
  }
  req.formKey = parsed.data;
  req.formSchema = FORM_SCHEMAS[parsed.data];
  next();
}

/**
 * Executa a query numa transação definindo app.tenant_id para a RLS.
 */
async function withTenant(tenantId, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

const guard = [requireAuth, requireActivePlan];

/* ------------------------------------------------------------------ *
 * 3. PUT /api/v1/drafts/:formKey  -> salva (upsert) o rascunho
 *    Body: { data: {...}, version?: number }
 *    "version" habilita controle otimista de concorrência (múltiplas abas).
 * ------------------------------------------------------------------ */
router.put('/drafts/:formKey', ...guard, resolveForm, async (req, res, next) => {
  try {
    const { data, version } = req.body ?? {};

    // Validação + normalização: .parse devolve um NOVO objeto contendo
    // apenas campos permitidos (sem __proto__/constructor injetados).
    const parsed = req.formSchema.safeParse(data);
    if (!parsed.success) {
      return res.status(422).json({
        error: 'Dados inválidos.',
        details: parsed.error.issues.map((i) => ({
          path: i.path.join('.'),
          message: i.message,
        })),
      });
    }

    const { tenantId, userId } = req.auth;
    const json = JSON.stringify(parsed.data); // Dates -> ISO 8601

    const row = await withTenant(tenantId, async (db) => {
      if (Number.isInteger(version)) {
        // Atualização condicionada à versão que o cliente conhece.
        const { rows } = await db.query(
          `UPDATE form_drafts
              SET data = $4::jsonb, version = version + 1, updated_at = now()
            WHERE tenant_id = $1 AND user_id = $2 AND form_key = $3
              AND version = $5
        RETURNING version, updated_at`,
          [tenantId, userId, req.formKey, json, version]
        );
        return rows[0] ?? null;
      }

      const { rows } = await db.query(
        `INSERT INTO form_drafts (tenant_id, user_id, form_key, data)
              VALUES ($1, $2, $3, $4::jsonb)
         ON CONFLICT (tenant_id, user_id, form_key)
       DO UPDATE SET data = EXCLUDED.data,
                     version = form_drafts.version + 1,
                     updated_at = now()
           RETURNING version, updated_at`,
        [tenantId, userId, req.formKey, json]
      );
      return rows[0];
    });

    if (!row) {
      return res.status(409).json({
        error: 'Conflito: o rascunho foi alterado em outra sessão.',
      });
    }

    res.json({ formKey: req.formKey, version: row.version, updatedAt: row.updated_at });
  } catch (err) {
    next(err);
  }
});

/* ------------------------------------------------------------------ *
 * 4. GET /api/v1/drafts/:formKey  -> restaura o rascunho
 *    Reconstrói o objeto a partir do JSON armazenado, revalidando com o
 *    schema ATUAL (o formulário pode ter evoluído desde que foi salvo).
 * ------------------------------------------------------------------ */
router.get('/drafts/:formKey', ...guard, resolveForm, async (req, res, next) => {
  try {
    const { tenantId, userId } = req.auth;

    const row = await withTenant(tenantId, async (db) => {
      const { rows } = await db.query(
        `SELECT data, version, updated_at
           FROM form_drafts
          WHERE tenant_id = $1 AND user_id = $2 AND form_key = $3`,
        [tenantId, userId, req.formKey]
      );
      return rows[0] ?? null;
    });

    if (!row) {
      return res.status(404).json({ error: 'Nenhum rascunho encontrado.' });
    }

    // O driver pg já devolve JSONB como objeto JS puro (via JSON.parse).
    // Revalida e reidrata tipos (ex.: string ISO -> Date) pelo schema.
    const restored = req.formSchema.safeParse(row.data);
    if (!restored.success) {
      // Rascunho incompatível com a versão atual do formulário.
      return res.status(410).json({
        error: 'Rascunho incompatível com a versão atual do formulário.',
      });
    }

    res.json({
      formKey: req.formKey,
      version: row.version,
      updatedAt: row.updated_at,
      data: restored.data, // Dates serializados novamente como ISO na resposta
    });
  } catch (err) {
    next(err);
  }
});

/* ------------------------------------------------------------------ *
 * 5. DELETE /api/v1/drafts/:formKey  -> descarta o rascunho
 * ------------------------------------------------------------------ */
router.delete('/drafts/:formKey', ...guard, resolveForm, async (req, res, next) => {
  try {
    const { tenantId, userId } = req.auth;
    await withTenant(tenantId, (db) =>
      db.query(
        `DELETE FROM form_drafts
          WHERE tenant_id = $1 AND user_id = $2 AND form_key = $3`,
        [tenantId, userId, req.formKey]
      )
    );
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

module.exports = router;

/*
 * Uso no app principal:
 *
 *   app.use('/api/v1', authenticateJwt, require('./drafts.routes'));
 */