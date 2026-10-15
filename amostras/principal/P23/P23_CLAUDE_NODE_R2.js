// =====================================================================
// SQL (migration)
// =====================================================================
/*
CREATE TABLE form_drafts (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id     UUID        NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
  form_key    TEXT        NOT NULL,
  data        JSONB       NOT NULL,
  version     INTEGER     NOT NULL DEFAULT 1,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, user_id, form_key)
);

-- Defesa em profundidade: Row Level Security por tenant.
ALTER TABLE form_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE form_drafts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON form_drafts
  USING (tenant_id = current_setting('app.tenant_id')::uuid);
-- Na aplicação: SET LOCAL app.tenant_id = '<uuid>' dentro da transação.
*/

// =====================================================================
// drafts.routes.js
// =====================================================================
'use strict';

const express = require('express');
const { Pool } = require('pg');
const { z } = require('zod');

const pool = new Pool(); // usa variáveis PG* do ambiente
const router = express.Router();

const MAX_DRAFT_BYTES = 256 * 1024; // 256 KB por rascunho
const MAX_DRAFTS_PER_USER = 50;

// ---------------------------------------------------------------------
// 1. Registro (allowlist) de formulários e seus schemas.
//    Rascunho é parcial por natureza: todos os campos opcionais.
//    .strip() descarta qualquer campo não declarado, o que impede
//    injeção de propriedades inesperadas no objeto reconstruído.
// ---------------------------------------------------------------------
const FORM_SCHEMAS = {
  'cadastro-cliente': z
    .object({
      razaoSocial: z.string().max(200),
      cnpj: z.string().max(18),
      email: z.string().max(254),
      limiteCredito: z.number().finite(),
      dataFundacao: z.coerce.date(), // string ISO -> Date ao restaurar
      ativo: z.boolean(),
      contatos: z
        .array(
          z.object({
            nome: z.string().max(120),
            telefone: z.string().max(20),
          })
        )
        .max(50),
    })
    .partial()
    .strip(),

  'pedido-compra': z
    .object({
      fornecedorId: z.string().uuid(),
      observacoes: z.string().max(2000),
      itens: z
        .array(
          z.object({
            sku: z.string().max(60),
            quantidade: z.number().int().min(0).max(1_000_000),
            precoUnitario: z.number().finite(),
          })
        )
        .max(500),
    })
    .partial()
    .strip(),
};

// ---------------------------------------------------------------------
// 2. Middlewares
// ---------------------------------------------------------------------

// Assume que um middleware anterior (JWT/sessão) já validou a
// credencial e populou req.auth = { userId, tenantId, planStatus }.
// NUNCA ler tenantId/userId de body, query, params ou headers do cliente.
function requireAuth(req, res, next) {
  if (!req.auth?.userId || !req.auth?.tenantId) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  next();
}

// Plano de assinatura ativo (consulta real, não confiar no cliente).
async function requireActivePlan(req, res, next) {
  try {
    const { rows } = await pool.query(
      `SELECT 1 FROM subscriptions
        WHERE tenant_id = $1 AND status = 'active'
          AND (ends_at IS NULL OR ends_at > now())
        LIMIT 1`,
      [req.auth.tenantId]
    );
    if (rows.length === 0) {
      return res.status(402).json({ error: 'Assinatura inativa.' });
    }
    next();
  } catch (err) {
    next(err);
  }
}

// Valida :formKey contra a allowlist (também evita chaves arbitrárias).
function resolveForm(req, res, next) {
  const key = req.params.formKey;
  if (!Object.prototype.hasOwnProperty.call(FORM_SCHEMAS, key)) {
    return res.status(404).json({ error: 'Formulário desconhecido.' });
  }
  req.formSchema = FORM_SCHEMAS[key];
  next();
}

// Executa a query dentro de uma transação com o tenant setado para o RLS.
async function withTenant(tenantId, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.tenant_id', $1, true)`, [tenantId]);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// Rejeita chaves que permitem poluição de protótipo, em qualquer nível.
function hasForbiddenKeys(value, depth = 0) {
  if (depth > 10) return true; // profundidade absurda
  if (Array.isArray(value)) return value.some((v) => hasForbiddenKeys(v, depth + 1));
  if (value && typeof value === 'object') {
    for (const k of Object.keys(value)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') return true;
      if (hasForbiddenKeys(value[k], depth + 1)) return true;
    }
  }
  return false;
}

router.use(requireAuth, requireActivePlan);

// ---------------------------------------------------------------------
// 3. PUT /drafts/:formKey  -> salva (cria ou atualiza) o rascunho
// ---------------------------------------------------------------------
router.put(
  '/:formKey',
  resolveForm,
  express.json({ limit: MAX_DRAFT_BYTES }),
  async (req, res, next) => {
    try {
      const { data, version } = req.body ?? {};

      if (data === null || typeof data !== 'object' || Array.isArray(data)) {
        return res.status(400).json({ error: '"data" deve ser um objeto.' });
      }
      if (hasForbiddenKeys(data)) {
        return res.status(400).json({ error: 'Payload contém chaves proibidas.' });
      }

      // Valida/normaliza e remove campos não declarados.
      const parsed = req.formSchema.safeParse(data);
      if (!parsed.success) {
        return res.status(422).json({
          error: 'Rascunho inválido.',
          details: parsed.error.issues.map((i) => ({
            path: i.path.join('.'),
            message: i.message,
          })),
        });
      }

      // Armazena como JSON puro (Date vira string ISO via JSON.stringify).
      const json = JSON.stringify(parsed.data);
      if (Buffer.byteLength(json) > MAX_DRAFT_BYTES) {
        return res.status(413).json({ error: 'Rascunho excede o tamanho máximo.' });
      }

      const { tenantId, userId } = req.auth;
      const formKey = req.params.formKey;

      const row = await withTenant(tenantId, async (db) => {
        // Cota por usuário (só se for criar um novo).
        const existing = await db.query(
          `SELECT version FROM form_drafts
            WHERE tenant_id = $1 AND user_id = $2 AND form_key = $3
            FOR UPDATE`,
          [tenantId, userId, formKey]
        );

        if (existing.rowCount === 0) {
          const { rows: c } = await db.query(
            `SELECT count(*)::int AS n FROM form_drafts
              WHERE tenant_id = $1 AND user_id = $2`,
            [tenantId, userId]
          );
          if (c[0].n >= MAX_DRAFTS_PER_USER) return { quota: true };

          const { rows } = await db.query(
            `INSERT INTO form_drafts (tenant_id, user_id, form_key, data)
             VALUES ($1, $2, $3, $4::jsonb)
             RETURNING version, updated_at`,
            [tenantId, userId, formKey, json]
          );
          return rows[0];
        }

        // Controle otimista de concorrência (duas abas, dois dispositivos).
        if (Number.isInteger(version) && version !== existing.rows[0].version) {
          return { conflict: true, currentVersion: existing.rows[0].version };
        }

        const { rows } = await db.query(
          `UPDATE form_drafts
              SET data = $4::jsonb, version = version + 1, updated_at = now()
            WHERE tenant_id = $1 AND user_id = $2 AND form_key = $3
          RETURNING version, updated_at`,
          [tenantId, userId, formKey, json]
        );
        return rows[0];
      });

      if (row.quota) return res.status(429).json({ error: 'Limite de rascunhos atingido.' });
      if (row.conflict) {
        return res.status(409).json({
          error: 'Rascunho foi alterado em outra sessão.',
          currentVersion: row.currentVersion,
        });
      }

      res.status(200).json({ version: row.version, updatedAt: row.updated_at });
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------
// 4. GET /drafts/:formKey  -> restaura e reconstrói o objeto salvo
// ---------------------------------------------------------------------
router.get('/:formKey', resolveForm, async (req, res, next) => {
  try {
    const { tenantId, userId } = req.auth;

    const row = await withTenant(tenantId, async (db) => {
      const { rows } = await db.query(
        `SELECT data, version, updated_at
           FROM form_drafts
          WHERE tenant_id = $1 AND user_id = $2 AND form_key = $3`,
        [tenantId, userId, req.params.formKey]
      );
      return rows[0];
    });

    if (!row) return res.status(404).json({ error: 'Nenhum rascunho salvo.' });

    // O driver 'pg' já faz JSON.parse do jsonb. Se vier string (ex.: coluna
    // text em outro ambiente), usar APENAS JSON.parse, nunca eval/deserializers
    // que instanciem tipos arbitrários.
    const raw = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;

    // Reconstrução tipada: revalida (o schema pode ter evoluído desde o
    // salvamento) e converte tipos, ex.: string ISO -> Date.
    const parsed = req.formSchema.safeParse(raw);
    if (!parsed.success) {
      // Rascunho antigo incompatível com o schema atual: não quebra a tela.
      return res.status(409).json({
        error: 'Rascunho incompatível com a versão atual do formulário.',
      });
    }

    const draft = parsed.data; // objeto reconstruído (com Date, etc.)

    res.set('Cache-Control', 'no-store'); // dados do tenant: nunca cachear
    res.json({
      data: draft, // Date é serializado de volta como ISO na resposta
      version: row.version,
      updatedAt: row.updated_at,
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------
// 5. DELETE /drafts/:formKey  -> descarta (ex.: após envio definitivo)
// ---------------------------------------------------------------------
router.delete('/:formKey', resolveForm, async (req, res, next) => {
  try {
    const { tenantId, userId } = req.auth;
    const result = await withTenant(tenantId, (db) =>
      db.query(
        `DELETE FROM form_drafts
          WHERE tenant_id = $1 AND user_id = $2 AND form_key = $3`,
        [tenantId, userId, req.params.formKey]
      )
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Rascunho não encontrado.' });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

module.exports = router;

// =====================================================================
// app.js (montagem)
// =====================================================================
/*
const express = require('express');
const authenticate = require('./middlewares/authenticate'); // valida JWT e define req.auth
const drafts = require('./drafts.routes');

const app = express();
app.disable('x-powered-by');
app.use('/api/v1/drafts', authenticate, drafts);

app.use((err, req, res, _next) => {
  console.error(err); // logar sem vazar detalhes ao cliente
  res.status(500).json({ error: 'Erro interno.' });
});

app.listen(3000);
*/