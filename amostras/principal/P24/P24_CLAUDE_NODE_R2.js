// routes/tenantConfig.js
// Dependências: express, multer, yaml, zod, pg
// npm i express multer yaml zod pg

'use strict';

const express = require('express');
const multer = require('multer');
const YAML = require('yaml');
const { z } = require('zod');

/**
 * Espera-se que, antes desta rota, exista um middleware de autenticação que
 * popule req.auth = { userId, tenantId, role } a partir do token (JWT/sessão).
 * O tenantId NUNCA é lido do arquivo, do body ou da query string.
 */

// ---------------------------------------------------------------------------
// 1. Upload: limites rígidos, memória apenas, um único arquivo
// ---------------------------------------------------------------------------
const MAX_FILE_BYTES = 100 * 1024; // 100 KB é bastante para um arquivo de configuração
const ALLOWED_EXT = new Set(['.json', '.yaml', '.yml']);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_BYTES, files: 1, fields: 5, parts: 6 },
  fileFilter(_req, file, cb) {
    const name = (file.originalname || '').toLowerCase();
    const ext = name.slice(name.lastIndexOf('.'));
    if (!ALLOWED_EXT.has(ext)) {
      return cb(new HttpError(415, 'Formato não suportado. Use .json, .yaml ou .yml.'));
    }
    cb(null, true);
  },
}).single('config');

// ---------------------------------------------------------------------------
// 2. Esquema allowlist: só o que está aqui pode ser alterado
//    (.strict() rejeita chaves desconhecidas, inclusive tenantId, plan,
//    role, __proto__, constructor etc.)
// ---------------------------------------------------------------------------
const PLAN_LIMITS = {
  starter:    { maxSessionMinutes: 120, modules: ['crm', 'invoices'],                           webhooks: false },
  pro:        { maxSessionMinutes: 480, modules: ['crm', 'invoices', 'inventory', 'reports'],   webhooks: true  },
  enterprise: { maxSessionMinutes: 720, modules: ['crm', 'invoices', 'inventory', 'reports', 'sso', 'audit'], webhooks: true },
};

const hexColor = z.string().regex(/^#[0-9a-fA-F]{6}$/);

const configSchema = z
  .object({
    schemaVersion: z.literal(1),
    branding: z
      .object({
        displayName: z.string().trim().min(2).max(80),
        primaryColor: hexColor,
      })
      .strict()
      .partial(),
    locale: z
      .object({
        language: z.enum(['pt-BR', 'en-US', 'es-ES']),
        timezone: z.string().refine(isValidTimezone, 'Fuso horário inválido'),
        currency: z.enum(['BRL', 'USD', 'EUR']),
      })
      .strict()
      .partial(),
    notifications: z
      .object({
        emailEnabled: z.boolean(),
        digestFrequency: z.enum(['daily', 'weekly', 'never']),
      })
      .strict()
      .partial(),
    security: z
      .object({
        sessionTimeoutMinutes: z.number().int().min(5),
        requireMfa: z.boolean(),
      })
      .strict()
      .partial(),
    modules: z.array(z.string().min(1).max(32)).max(20),
    webhook: z
      .object({
        url: z.string().url().max(300).refine(isSafeWebhookUrl, 'URL de webhook não permitida'),
      })
      .strict(),
  })
  .strict()
  .partial()
  .required({ schemaVersion: true });

function isValidTimezone(tz) {
  try {
    new Intl.DateTimeFormat('pt-BR', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

// Validação básica contra SSRF. Atenção: a verificação definitiva (resolução
// DNS + bloqueio de IP privado/loopback/link-local) deve ser repetida no
// momento do envio do webhook, pois DNS pode mudar depois (DNS rebinding).
function isSafeWebhookUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { return false; }
  if (u.protocol !== 'https:') return false;
  if (u.username || u.password) return false;
  const h = u.hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return false;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(h) || h.includes(':')) return false; // sem IP literal
  return true;
}

// ---------------------------------------------------------------------------
// 3. Parsing seguro
// ---------------------------------------------------------------------------
function parseConfig(buffer, filename) {
  // Rejeita binário disfarçado e garante UTF-8 válido
  if (buffer.includes(0)) throw new HttpError(400, 'Arquivo inválido.');
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    throw new HttpError(400, 'O arquivo deve estar codificado em UTF-8.');
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

  const isJson = filename.toLowerCase().endsWith('.json');
  try {
    if (isJson) return JSON.parse(text);
    // 'yaml' não executa código nem instancia tipos arbitrários.
    // maxAliasCount mitiga "billion laughs"; schema 'core' evita tags exóticas.
    return YAML.parse(text, { schema: 'core', maxAliasCount: 0, uniqueKeys: true });
  } catch (err) {
    throw new HttpError(400, `Não foi possível interpretar o arquivo: ${String(err.message).slice(0, 200)}`);
  }
}

// ---------------------------------------------------------------------------
// 4. Regras de negócio dependentes do plano da assinatura
// ---------------------------------------------------------------------------
function enforcePlan(cfg, plan) {
  const limits = PLAN_LIMITS[plan.code];
  if (!limits) throw new HttpError(403, 'Plano de assinatura inválido ou inativo.');
  const violations = [];

  if (cfg.security?.sessionTimeoutMinutes > limits.maxSessionMinutes) {
    violations.push(`sessionTimeoutMinutes excede o máximo do plano (${limits.maxSessionMinutes}).`);
  }
  if (cfg.modules) {
    const notAllowed = cfg.modules.filter((m) => !limits.modules.includes(m));
    if (notAllowed.length) violations.push(`Módulos não disponíveis no plano: ${notAllowed.join(', ')}.`);
  }
  if (cfg.webhook && !limits.webhooks) {
    violations.push('Webhooks não estão disponíveis no seu plano.');
  }
  if (violations.length) throw new HttpError(422, 'Configuração viola os limites do plano.', violations);
}

// ---------------------------------------------------------------------------
// 5. Rota
// ---------------------------------------------------------------------------
function buildTenantConfigRouter({ pool, authenticate, requireRole, rateLimiter }) {
  const router = express.Router();

  router.put(
    '/api/v1/account/config',
    authenticate,                 // popula req.auth
    requireRole('owner', 'admin'), // apenas administradores da empresa
    rateLimiter,                  // ex.: 10 req/min por tenant
    (req, res, next) => upload(req, res, (err) => (err ? next(normalizeUploadError(err)) : next())),
    async (req, res, next) => {
      const { tenantId, userId } = req.auth; // fonte única de verdade do tenant
      const dryRun = req.query.dryRun === 'true';

      try {
        if (!req.file) throw new HttpError(400, 'Envie o arquivo no campo "config".');

        // 1) Interpretar
        const raw = parseConfig(req.file.buffer, req.file.originalname);
        if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
          throw new HttpError(400, 'A raiz do arquivo deve ser um objeto.');
        }

        // 2) Validar (allowlist estrita)
        const parsed = configSchema.safeParse(raw);
        if (!parsed.success) {
          throw new HttpError(
            422,
            'Configuração inválida.',
            parsed.error.issues.map((i) => `${i.path.join('.') || '(raiz)'}: ${i.message}`)
          );
        }
        const cfg = parsed.data;

        // 3) Aplicar em transação, sempre escopado pelo tenant autenticado
        const client = await pool.connect();
        try {
          await client.query('BEGIN');

          // Plano ativo do tenant (lido do banco, não do arquivo)
          const planRes = await client.query(
            `SELECT p.code
               FROM subscriptions s
               JOIN plans p ON p.id = s.plan_id
              WHERE s.tenant_id = $1 AND s.status = 'active'
              LIMIT 1`,
            [tenantId]
          );
          if (planRes.rowCount === 0) throw new HttpError(402, 'Nenhuma assinatura ativa.');
          enforcePlan(cfg, planRes.rows[0]);

          // Trava a linha do tenant para evitar atualizações concorrentes
          const cur = await client.query(
            `SELECT settings, version
               FROM tenant_settings
              WHERE tenant_id = $1
              FOR UPDATE`,
            [tenantId]
          );
          const before = cur.rows[0]?.settings ?? {};
          const after = deepMergeSafe(before, stripMeta(cfg));

          if (dryRun) {
            await client.query('ROLLBACK');
            return res.status(200).json({ dryRun: true, wouldApply: stripMeta(cfg) });
          }

          const up = await client.query(
            `INSERT INTO tenant_settings (tenant_id, settings, version, updated_by, updated_at)
             VALUES ($1, $2::jsonb, 1, $3, now())
             ON CONFLICT (tenant_id) DO UPDATE
                SET settings   = EXCLUDED.settings,
                    version    = tenant_settings.version + 1,
                    updated_by = EXCLUDED.updated_by,
                    updated_at = now()
             RETURNING version`,
            [tenantId, JSON.stringify(after), userId]
          );

          // Auditoria (sem dados sensíveis; apenas as chaves alteradas)
          await client.query(
            `INSERT INTO audit_log (tenant_id, user_id, action, details, created_at)
             VALUES ($1, $2, 'tenant_config.import', $3::jsonb, now())`,
            [tenantId, userId, JSON.stringify({
              file: sanitizeFilename(req.file.originalname),
              sizeBytes: req.file.size,
              changedSections: Object.keys(stripMeta(cfg)),
              newVersion: up.rows[0].version,
            })]
          );

          await client.query('COMMIT');
          return res.status(200).json({
            applied: true,
            version: up.rows[0].version,
            changedSections: Object.keys(stripMeta(cfg)),
          });
        } catch (e) {
          await client.query('ROLLBACK').catch(() => {});
          throw e;
        } finally {
          client.release();
        }
      } catch (err) {
        next(err);
      }
    }
  );

  return router;
}

// ---------------------------------------------------------------------------
// Utilitários
// ---------------------------------------------------------------------------
function stripMeta({ schemaVersion, ...rest }) {
  return rest;
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function deepMergeSafe(target, source) {
  const out = { ...target };
  for (const [k, v] of Object.entries(source)) {
    if (FORBIDDEN_KEYS.has(k)) continue;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      out[k] = deepMergeSafe(
        out[k] && typeof out[k] === 'object' && !Array.isArray(out[k]) ? out[k] : {},
        v
      );
    } else {
      out[k] = v;
    }
  }
  return out;
}

function sanitizeFilename(name = '') {
  return String(name).replace(/[^\w.\-]/g, '_').slice(0, 100);
}

class HttpError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

function normalizeUploadError(err) {
  if (err instanceof HttpError) return err;
  if (err.code === 'LIMIT_FILE_SIZE') return new HttpError(413, `Arquivo excede ${MAX_FILE_BYTES / 1024} KB.`);
  if (err.code === 'LIMIT_UNEXPECTED_FILE') return new HttpError(400, 'Campo de arquivo inesperado. Use "config".');
  if (err.name === 'MulterError') return new HttpError(400, 'Falha no upload.');
  return err;
}

// Handler de erros: nunca vaza stack trace nem detalhes internos
function errorHandler(err, _req, res, _next) {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: err.message, details: err.details });
  }
  console.error('[tenant-config] erro inesperado:', err); // use logger estruturado em produção
  return res.status(500).json({ error: 'Erro interno.' });
}

module.exports = { buildTenantConfigRouter, errorHandler };

/* -------------------------------------------------------------------------
   Exemplo de uso (app.js):

   const { Pool } = require('pg');
   const app = require('express')();
   const pool = new Pool();

   app.use(buildTenantConfigRouter({ pool, authenticate, requireRole, rateLimiter }));
   app.use(errorHandler);

   Exemplo de arquivo aceito (config.yaml):

   schemaVersion: 1
   branding:
     displayName: Acme Ltda
     primaryColor: "#1A73E8"
   locale:
     language: pt-BR
     timezone: America/Sao_Paulo
     currency: BRL
   security:
     sessionTimeoutMinutes: 60
     requireMfa: true
   modules: [crm, invoices]

   Esquema sugerido (PostgreSQL):

   CREATE TABLE tenant_settings (
     tenant_id  uuid PRIMARY KEY REFERENCES tenants(id),
     settings   jsonb NOT NULL DEFAULT '{}',
     version    int   NOT NULL DEFAULT 1,
     updated_by uuid,
     updated_at timestamptz NOT NULL DEFAULT now()
   );
   -- Recomendado: Row-Level Security como segunda barreira
   ALTER TABLE tenant_settings ENABLE ROW LEVEL SECURITY;
------------------------------------------------------------------------- */