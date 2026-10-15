// drafts.routes.js
'use strict';

const express = require('express');
const { z } = require('zod');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

/* ------------------------------------------------------------------ */
/* Middlewares (supõe que a autenticação JWT já populou req.auth)      */
/* ------------------------------------------------------------------ */

// req.auth = { userId, tenantId } extraídos do token VERIFICADO.
function requireAuth(req, res, next) {
  if (!req.auth?.userId || !req.auth?.tenantId) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  next();
}

async function requireActivePlan(req, res, next) {
  try {
    const { rows } = await pool.query(
      `SELECT 1 FROM subscriptions
        WHERE tenant_id = $1 AND status = 'active' AND (ends_at IS NULL OR ends_at > now())`,
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

/* ------------------------------------------------------------------ */
/* Registro de formulários permitidos (allowlist de form_key + schema) */
/* ------------------------------------------------------------------ */

const FORMS = {
  'cadastro-cliente': {
    schema: z
      .object({
        nome: z.string().max(200).optional(),
        email: z.string().email().max(254).optional().or(z.literal('')),
        telefone: z.string().max(30).optional(),
        observacoes: z.string().max(5000).optional(),
        endereco: z
          .object({
            rua: z.string().max(200).optional(),
            numero: z.string().max(20).optional(),
            cidade: z.string().max(100).optional(),
            uf: z.string().length(2).optional(),
          })
          .strict()
          .optional(),
        itens: z
          .array(
            z.object({ produtoId: z.string().uuid(), quantidade: z.number().int().min(0).max(100000) }).strict()
          )
          .max(200)
          .optional(),
      })
      .strict(),
    // Fábrica: reconstrói o objeto de domínio explicitamente, sem executar nada.
    rebuild(data) {
      return {
        nome: data.nome ?? '',
        email: data.email ?? '',
        telefone: data.telefone ?? '',
        observacoes: data.observacoes ?? '',
        endereco: {
          rua: data.endereco?.rua ?? '',
          numero: data.endereco?.numero ?? '',
          cidade: data.endereco?.cidade ?? '',
          uf: data.endereco?.uf ?? '',
        },
        itens: (data.itens ?? []).map((i) => ({
          produtoId: i.produtoId,
          quantidade: i.quantidade,
        })),
      };
    },
  },
};

function resolveForm(req, res, next) {
  const key = req.params.formKey;
  // Object.hasOwn evita acessar chaves herdadas ("__proto__", "constructor")
  if (!Object.hasOwn(FORMS, key)) {
    return res.status(404).json({ error: 'Formulário desconhecido.' });
  }
  req.form = FORMS[key];
  next();
}

const bodySchema = z
  .object({
    data: z.unknown(),
    expectedVersion: z.number().int().min(0).optional(), // 0 = ainda não existe
  })
  .strict();

const router_ = router;
router_.use(requireAuth, requireActivePlan);

/* ------------------------------------------------------------------ */
/* PUT /api/forms/:formKey/draft  — salvar (upsert)                    */
/* ------------------------------------------------------------------ */
router_.put('/forms/:formKey/draft', resolveForm, express.json({ limit: '256kb' }), async (req, res, next) => {
  try {
    const body = bodySchema.safeParse(req.body);
    if (!body.success) {
      return res.status(400).json({ error: 'Corpo inválido.' });
    }

    const parsed = req.form.schema.safeParse(body.data.data);
    if (!parsed.success) {
      return res.status(422).json({ error: 'Dados do formulário inválidos.', details: parsed.error.issues });
    }

    const { tenantId, userId } = req.auth;
    const { formKey } = req.params;
    const expected = body.data.expectedVersion;

    let result;
    if (expected === undefined) {
      // Last-write-wins
      result = await pool.query(
        `INSERT INTO form_drafts (tenant_id, user_id, form_key, data)
         VALUES ($1, $2, $3, $4::jsonb)
         ON CONFLICT (tenant_id, user_id, form_key)
         DO UPDATE SET data = EXCLUDED.data, version = form_drafts.version + 1, updated_at = now()
         RETURNING version, updated_at`,
        [tenantId, userId, formKey, JSON.stringify(parsed.data)]
      );
    } else if (expected === 0) {
      result = await pool.query(
        `INSERT INTO form_drafts (tenant_id, user_id, form_key, data)
         VALUES ($1, $2, $3, $4::jsonb)
         ON CONFLICT DO NOTHING
         RETURNING version, updated_at`,
        [tenantId, userId, formKey, JSON.stringify(parsed.data)]
      );
    } else {
      result = await pool.query(
        `UPDATE form_drafts
            SET data = $4::jsonb, version = version + 1, updated_at = now()
          WHERE tenant_id = $1 AND user_id = $2 AND form_key = $3 AND version = $5
        RETURNING version, updated_at`,
        [tenantId, userId, formKey, JSON.stringify(parsed.data), expected]
      );
    }

    if (result.rowCount === 0) {
      return res.status(409).json({ error: 'Conflito de versão: o rascunho foi alterado em outra sessão.' });
    }

    res.json({ version: result.rows[0].version, updatedAt: result.rows[0].updated_at });
  } catch (err) {
    next(err);
  }
});

/* ------------------------------------------------------------------ */
/* GET /api/forms/:formKey/draft  — restaurar                          */
/* ------------------------------------------------------------------ */
router_.get('/forms/:formKey/draft', resolveForm, async (req, res, next) => {
  try {
    const { tenantId, userId } = req.auth;
    const { rows } = await pool.query(
      `SELECT data, version, updated_at
         FROM form_drafts
        WHERE tenant_id = $1 AND user_id = $2 AND form_key = $3`,
      [tenantId, userId, req.params.formKey]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Nenhum rascunho encontrado.' });
    }

    // O schema pode ter evoluído desde que o rascunho foi salvo: revalida na leitura.
    const parsed = req.form.schema.safeParse(rows[0].data);
    if (!parsed.success) {
      return res.status(410).json({ error: 'Rascunho incompatível com a versão atual do formulário.' });
    }

    res.json({
      draft: req.form.rebuild(parsed.data), // objeto reconstruído de forma explícita
      version: rows[0].version,
      updatedAt: rows[0].updated_at,
    });
  } catch (err) {
    next(err);
  }
});

/* ------------------------------------------------------------------ */
/* DELETE /api/forms/:formKey/draft  — descartar                       */
/* ------------------------------------------------------------------ */
router_.delete('/forms/:formKey/draft', resolveForm, async (req, res, next) => {
  try {
    const { tenantId, userId } = req.auth;
    await pool.query(
      `DELETE FROM form_drafts WHERE tenant_id = $1 AND user_id = $2 AND form_key = $3`,
      [tenantId, userId, req.params.formKey]
    );
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

module.exports = router_;