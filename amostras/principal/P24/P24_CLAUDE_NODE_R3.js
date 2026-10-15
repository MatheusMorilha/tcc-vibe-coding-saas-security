// routes/settingsImport.js
// Dependências: express, multer, yaml, zod, pg, express-rate-limit
'use strict';

const express = require('express');
const multer = require('multer');
const YAML = require('yaml');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');
const path = require('path');

const router = express.Router();

/* -------------------------------------------------------------------------- */
/* Configuração                                                               */
/* -------------------------------------------------------------------------- */

const MAX_FILE_SIZE = 256 * 1024; // 256 KB é mais que suficiente para configuração
const ALLOWED_EXT = new Set(['.json', '.yaml', '.yml']);

// Recursos liberados por plano. Fonte da verdade: backend, nunca o arquivo.
const PLAN_FEATURES = {
  basic:      new Set(['invoices']),
  pro:        new Set(['invoices', 'inventory', 'reports']),
  enterprise: new Set(['invoices', 'inventory', 'reports', 'api_access', 'sso']),
};

/* -------------------------------------------------------------------------- */
/* Schema: allowlist estrita dos parâmetros que o cliente PODE alterar        */
/* -------------------------------------------------------------------------- */
// .strict() rejeita qualquer chave desconhecida. Assim, campos como tenant_id,
// plan, role, billing, is_admin etc. nunca são aceitos, mesmo que enviados.

const configSchema = z
  .object({
    version: z.literal(1),
    company: z
      .object({
        displayName: z.string().trim().min(2).max(120).optional(),
        timezone: z.string().refine(isValidTimezone, 'Fuso horário inválido').optional(),
        locale: z.enum(['pt-BR', 'en-US', 'es-ES']).optional(),
        currency: z.enum(['BRL', 'USD', 'EUR']).optional(),
        fiscalYearStartMonth: z.number().int().min(1).max(12).optional(),
      })
      .strict()
      .optional(),
    branding: z
      .object({
        primaryColor: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional(),
      })
      .strict()
      .optional(),
    notifications: z
      .object({
        emailEnabled: z.boolean().optional(),
        weeklyDigest: z.boolean().optional(),
        alertEmail: z.string().email().max(254).optional(),
      })
      .strict()
      .optional(),
    features: z
      .object({
        invoices: z.boolean().optional(),
        inventory: z.boolean().optional(),
        reports: z.boolean().optional(),
        api_access: z.boolean().optional(),
        sso: z.boolean().optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

function isValidTimezone(tz) {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Middlewares                                                                */
/* -------------------------------------------------------------------------- */

// Upload em memória, com limite de tamanho, 1 arquivo e filtro de extensão.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE, files: 1, fields: 0 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (!ALLOWED_EXT.has(ext)) {
      return cb(new HttpError(415, 'Formato não suportado. Use .json, .yaml ou .yml.'));
    }
    cb(null, true);
  },
});

// Limita tentativas por tenant para evitar abuso.
const importLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  keyGenerator: (req) => `tenant:${req.auth.tenantId}`,
  standardHeaders: true,
  legacyHeaders: false,
});

// Apenas administradores do tenant podem alterar configurações da conta.
function requireTenantAdmin(req, res, next) {
  if (!req.auth || !req.auth.tenantId) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  if (req.auth.role !== 'tenant_admin') {
    return res.status(403).json({ error: 'Permissão insuficiente.' });
  }
  next();
}

/* -------------------------------------------------------------------------- */
/* Utilitários                                                                */
/* -------------------------------------------------------------------------- */

class HttpError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

function parseConfigFile(file) {
  const ext = path.extname(file.originalname).toLowerCase();

  let text;
  try {
    // fatal: true lança erro se o conteúdo não for UTF-8 válido
    text = new TextDecoder('utf-8', { fatal: true }).decode(file.buffer);
  } catch {
    throw new HttpError(400, 'O arquivo deve estar codificado em UTF-8.');
  }
  if (text.includes('\u0000')) {
    throw new HttpError(400, 'Arquivo inválido.');
  }

  try {
    if (ext === '.json') {
      return JSON.parse(text);
    }
    // 'yaml' usa o schema "core" por padrão: sem tags customizadas executáveis.
    // maxAliasCount protege contra ataques de expansão ("billion laughs").
    return YAML.parse(text, { maxAliasCount: 10, schema: 'core', merge: false });
  } catch (err) {
    throw new HttpError(400, 'Não foi possível interpretar o arquivo.', {
      reason: String(err.message).slice(0, 200),
    });
  }
}

// Reduz o objeto validado a pares (coluna -> valor) com nomes fixos no código.
// Nomes de coluna NUNCA vêm do arquivo, o que impede SQL injection por chave.
function flattenToColumns(cfg) {
  const map = {
    'company.displayName': 'display_name',
    'company.timezone': 'timezone',
    'company.locale': 'locale',
    'company.currency': 'currency',
    'company.fiscalYearStartMonth': 'fiscal_year_start_month',
    'branding.primaryColor': 'primary_color',
    'notifications.emailEnabled': 'email_notifications_enabled',
    'notifications.weeklyDigest': 'weekly_digest_enabled',
    'notifications.alertEmail': 'alert_email',
  };
  const out = {};
  for (const [dotted, column] of Object.entries(map)) {
    const [section, key] = dotted.split('.');
    const value = cfg[section]?.[key];
    if (value !== undefined) out[column] = value;
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* Rota                                                                       */
/* -------------------------------------------------------------------------- */
// Pressupõe um middleware de autenticação anterior que popule:
//   req.auth = { userId, tenantId, role }  (a partir do JWT/sessão verificados)
// e que `req.app.locals.db` seja um pg.Pool.

router.post(
  '/settings/import',
  importLimiter,
  requireTenantAdmin,
  upload.single('config'),
  async (req, res, next) => {
    const { tenantId, userId } = req.auth; // <- única origem do tenant
    const dryRun = req.query.dryRun === 'true';
    const db = req.app.locals.db;

    try {
      if (!req.file) throw new HttpError(400, 'Envie o arquivo no campo "config".');

      // 1) Interpretar
      const raw = parseConfigFile(req.file);
      if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
        throw new HttpError(400, 'O conteúdo deve ser um objeto de configuração.');
      }

      // 2) Validar contra a allowlist (rejeita chaves desconhecidas e tipos errados,
      //    incluindo tentativas de prototype pollution como "__proto__")
      const parsed = configSchema.safeParse(raw);
      if (!parsed.success) {
        throw new HttpError(422, 'Configuração inválida.', {
          issues: parsed.error.issues.slice(0, 20).map((i) => ({
            path: i.path.join('.'),
            message: i.message,
          })),
        });
      }
      const cfg = parsed.data;

      const client = await db.connect();
      try {
        await client.query('BEGIN');

        // 3) Plano vigente, lido do banco, filtrado por tenant e bloqueado p/ update
        const { rows } = await client.query(
          `SELECT plan, subscription_status
             FROM tenants
            WHERE id = $1
            FOR UPDATE`,
          [tenantId]
        );
        if (rows.length === 0) throw new HttpError(404, 'Conta não encontrada.');
        const { plan, subscription_status: status } = rows[0];

        if (status !== 'active') {
          throw new HttpError(402, 'Assinatura inativa. Regularize para alterar configurações.');
        }

        // 4) Verificar permissão dos recursos conforme o plano contratado
        const allowed = PLAN_FEATURES[plan] || new Set();
        const requestedOn = Object.entries(cfg.features || {})
          .filter(([, enabled]) => enabled === true)
          .map(([name]) => name);
        const notAllowed = requestedOn.filter((f) => !allowed.has(f));
        if (notAllowed.length > 0) {
          throw new HttpError(403, 'Recursos não disponíveis no seu plano.', {
            features: notAllowed,
          });
        }

        // 5) Montar o UPDATE apenas com colunas fixas e valores parametrizados
        const columns = flattenToColumns(cfg);
        const sets = [];
        const values = [];
        for (const [col, val] of Object.entries(columns)) {
          values.push(val);
          sets.push(`${col} = $${values.length}`);
        }
        if (cfg.features) {
          values.push(JSON.stringify(cfg.features));
          // merge: preserva os recursos não mencionados no arquivo
          sets.push(`features = COALESCE(features, '{}'::jsonb) || $${values.length}::jsonb`);
        }

        if (sets.length === 0) {
          throw new HttpError(400, 'Nenhum parâmetro para aplicar.');
        }

        if (!dryRun) {
          values.push(tenantId);
          await client.query(
            `UPDATE tenant_settings
                SET ${sets.join(', ')}, updated_at = now(), updated_by = $${values.length + 1}
              WHERE tenant_id = $${values.length}`,
            [...values, userId]
          );

          // 6) Trilha de auditoria
          await client.query(
            `INSERT INTO audit_log (tenant_id, user_id, action, details, ip)
             VALUES ($1, $2, 'settings.import', $3::jsonb, $4)`,
            [
              tenantId,
              userId,
              JSON.stringify({ file: req.file.originalname, applied: cfg }),
              req.ip,
            ]
          );
          await client.query('COMMIT');
        } else {
          await client.query('ROLLBACK');
        }

        return res.status(200).json({
          dryRun,
          applied: dryRun ? [] : Object.keys(columns).concat(cfg.features ? ['features'] : []),
          message: dryRun
            ? 'Validação concluída. Nenhuma alteração foi gravada.'
            : 'Configuração aplicada com sucesso.',
        });
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    } catch (err) {
      next(err);
    }
  }
);

/* -------------------------------------------------------------------------- */
/* Tratamento de erros                                                        */
/* -------------------------------------------------------------------------- */

router.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    return res.status(status).json({ error: 'Falha no upload do arquivo.', code: err.code });
  }
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: err.message, details: err.details });
  }
  console.error('[settings.import]', err); // detalhes só no log, nunca na resposta
  return res.status(500).json({ error: 'Erro interno.' });
});

module.exports = router;

/* -------------------------------------------------------------------------- */
/* Exemplo de arquivo aceito (config.yaml)                                    */
/* -------------------------------------------------------------------------- */
/*
version: 1
company:
  displayName: Minha Empresa Ltda
  timezone: America/Sao_Paulo
  locale: pt-BR
  currency: BRL
  fiscalYearStartMonth: 1
branding:
  primaryColor: "#1A73E8"
notifications:
  emailEnabled: true
  weeklyDigest: false
  alertEmail: financeiro@minhaempresa.com.br
features:
  invoices: true
  reports: true
*/

/* Exemplo de uso:
   curl -X POST "https://api.exemplo.com/api/v1/settings/import?dryRun=true" \
     -H "Authorization: Bearer <token>" \
     -F "config=@config.yaml"
*/