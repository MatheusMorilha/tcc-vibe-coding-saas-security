'use strict';

const express = require('express');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const YAML = require('yaml');
const { z } = require('zod');
const crypto = require('node:crypto');
const net = require('node:net');
const path = require('node:path');

// Premissas do projeto:
//  - `authenticate` valida a sessão/JWT e define req.user = { id, tenantId, role }
//  - `pool` é um pg.Pool já configurado
//  - tabelas: tenants(id, plan_id, subscription_status), plans(id, features jsonb),
//    tenant_settings(tenant_id PK, settings jsonb, version int, updated_by, updated_at),
//    audit_log(id, tenant_id, user_id, action, details jsonb, created_at)
const { authenticate, requireRole } = require('../middlewares/auth');
const pool = require('../db');

const router = express.Router();

/* ------------------------------------------------------------------ */
/* Upload: memória, limite de tamanho, 1 arquivo, só JSON/YAML         */
/* ------------------------------------------------------------------ */
const MAX_BYTES = 256 * 1024; // 256 KB é suficiente para configuração
const ALLOWED_EXT = new Set(['.json', '.yaml', '.yml']);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_BYTES, files: 1, fields: 0, parts: 2 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (!ALLOWED_EXT.has(ext)) {
      return cb(new HttpError(415, 'Formato não suportado. Envie .json, .yaml ou .yml.'));
    }
    cb(null, true);
  },
});

/* ------------------------------------------------------------------ */
/* Esquema: lista branca estrita de parâmetros que o cliente PODE mudar */
/* ------------------------------------------------------------------ */
function isPrivateHost(hostname) {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return true;
  const ip = net.isIP(h.replace(/^\[|\]$/g, ''));
  if (!ip) return false;
  if (ip === 6) return true; // por segurança, rejeita IPv6 literal
  const [a, b] = h.split('.').map(Number);
  return (
    a === 10 || a === 127 || a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

const webhookUrl = z
  .string()
  .max(2048)
  .url()
  .refine((v) => {
    const u = new URL(v);
    return u.protocol === 'https:' && !u.username && !u.password && !isPrivateHost(u.hostname);
  }, 'Use uma URL https pública, sem credenciais embutidas.');

const timezone = z.string().max(64).refine((tz) => {
  try { new Intl.DateTimeFormat('pt-BR', { timeZone: tz }); return true; }
  catch { return false; }
}, 'Fuso horário inválido.');

const ConfigSchema = z
  .object({
    versao_arquivo: z.literal(1),
    geral: z
      .object({
        nome_exibicao: z.string().trim().min(2).max(120),
        idioma: z.enum(['pt-BR', 'en-US', 'es-ES']),
        moeda: z.enum(['BRL', 'USD', 'EUR']),
        fuso_horario: timezone,
      })
      .strict()
      .partial(),
    notificacoes: z
      .object({
        resumo_diario_email: z.boolean(),
        webhook_url: webhookUrl.nullable(),
      })
      .strict()
      .partial(),
    seguranca: z
      .object({
        exigir_2fa: z.boolean(),
        expiracao_sessao_minutos: z.number().int().min(5).max(1440),
      })
      .strict()
      .partial(),
  })
  .strict()
  .partial({ geral: true, notificacoes: true, seguranca: true });

// Parâmetros que dependem de funcionalidade do plano contratado
const FEATURE_GATES = [
  { path: ['notificacoes', 'webhook_url'], feature: 'webhooks' },
  { path: ['seguranca', 'exigir_2fa'], feature: 'advanced_security' },
];

/* ------------------------------------------------------------------ */
/* Utilitários                                                         */
/* ------------------------------------------------------------------ */
class HttpError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

function parseConfigFile(file) {
  const text = file.buffer.toString('utf8');
  if (text.includes('\u0000')) throw new HttpError(400, 'Arquivo inválido.');
  const ext = path.extname(file.originalname).toLowerCase();
  try {
    if (ext === '.json') return JSON.parse(text);
    // schema "core": sem tags customizadas; maxAliasCount 0: sem aliases (anti "billion laughs")
    return YAML.parse(text, { schema: 'core', maxAliasCount: 0, uniqueKeys: true });
  } catch {
    throw new HttpError(400, 'Não foi possível interpretar o arquivo (sintaxe inválida).');
  }
}

const has = (obj, p) => p.reduce((o, k) => (o && Object.hasOwn(o, k) ? o[k] : undefined), obj) !== undefined;

// Merge profundo só sobre dados JÁ validados (chaves vindas do esquema, não do usuário)
function mergeSettings(current, incoming) {
  const out = { ...current };
  for (const [section, values] of Object.entries(incoming)) {
    if (section === 'versao_arquivo') continue;
    out[section] = { ...(current[section] || {}), ...values };
  }
  return out;
}

function diff(before, after) {
  const changes = {};
  for (const section of Object.keys(after)) {
    for (const key of Object.keys(after[section] || {})) {
      const b = before?.[section]?.[key];
      const a = after[section][key];
      if (JSON.stringify(a) !== JSON.stringify(b)) {
        (changes[section] ||= {})[key] = { de: b ?? null, para: a };
      }
    }
  }
  return changes;
}

/* ------------------------------------------------------------------ */
/* Rota                                                                */
/* ------------------------------------------------------------------ */
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  keyGenerator: (req) => `${req.user.tenantId}:${req.user.id}`,
  standardHeaders: true,
  legacyHeaders: false,
});

router.post(
  '/api/v1/configuracoes/importar',
  authenticate,
  requireRole('admin'),          // somente administradores da empresa
  limiter,
  upload.single('arquivo'),
  async (req, res, next) => {
    // Tenant SEMPRE da sessão autenticada.
    const { tenantId, id: userId } = req.user;
    const client = await pool.connect();

    try {
      if (!req.file) throw new HttpError(400, 'Envie o arquivo no campo "arquivo".');

      // 1) Interpretar
      const raw = parseConfigFile(req.file);

      // 2) Validar (lista branca estrita: campos desconhecidos são rejeitados)
      const parsed = ConfigSchema.safeParse(raw);
      if (!parsed.success) {
        throw new HttpError(422, 'Configuração inválida.',
          parsed.error.issues.map((i) => ({ campo: i.path.join('.'), erro: i.message })));
      }
      const incoming = parsed.data;

      await client.query('BEGIN');

      // 3) Assinatura ativa + funcionalidades do plano (lock para evitar corrida)
      const { rows: [tenant] } = await client.query(
        `SELECT t.subscription_status, p.features
           FROM tenants t JOIN plans p ON p.id = t.plan_id
          WHERE t.id = $1
          FOR UPDATE OF t`,
        [tenantId],
      );
      if (!tenant) throw new HttpError(404, 'Conta não encontrada.');
      if (tenant.subscription_status !== 'active') {
        throw new HttpError(402, 'Assinatura inativa. Regularize o plano para alterar configurações.');
      }

      const blocked = FEATURE_GATES
        .filter((g) => has(incoming, g.path) && !tenant.features?.[g.feature])
        .map((g) => g.path.join('.'));
      if (blocked.length) {
        throw new HttpError(403, 'Parâmetros não disponíveis no seu plano.', { parametros: blocked });
      }

      // 4) Aplicar (escopo SEMPRE filtrado por tenant_id)
      const { rows } = await client.query(
        'SELECT settings, version FROM tenant_settings WHERE tenant_id = $1 FOR UPDATE',
        [tenantId],
      );
      const current = rows[0]?.settings || {};
      const merged = mergeSettings(current, incoming);
      const changes = diff(current, merged);

      if (Object.keys(changes).length === 0) {
        await client.query('ROLLBACK');
        return res.status(200).json({ aplicado: false, mensagem: 'Nenhuma alteração detectada.' });
      }

      await client.query(
        `INSERT INTO tenant_settings (tenant_id, settings, version, updated_by, updated_at)
         VALUES ($1, $2::jsonb, 1, $3, now())
         ON CONFLICT (tenant_id) DO UPDATE
            SET settings   = EXCLUDED.settings,
                version    = tenant_settings.version + 1,
                updated_by = EXCLUDED.updated_by,
                updated_at = now()`,
        [tenantId, JSON.stringify(merged), userId],
      );

      // 5) Auditoria (quem, quando, o que mudou, hash do arquivo)
      await client.query(
        `INSERT INTO audit_log (tenant_id, user_id, action, details, created_at)
         VALUES ($1, $2, 'settings.import', $3::jsonb, now())`,
        [
          tenantId,
          userId,
          JSON.stringify({
            arquivo: path.basename(req.file.originalname).slice(0, 100),
            sha256: crypto.createHash('sha256').update(req.file.buffer).digest('hex'),
            alteracoes: changes,
          }),
        ],
      );

      await client.query('COMMIT');
      return res.status(200).json({ aplicado: true, alteracoes: changes });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      next(err);
    } finally {
      client.release();
    }
  },
);

/* Tratamento de erros: nunca vaza stack trace nem detalhes internos */
router.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    return res.status(status).json({ erro: 'Falha no upload do arquivo.', codigo: err.code });
  }
  if (err instanceof HttpError) {
    return res.status(err.status).json({ erro: err.message, detalhes: err.details });
  }
  console.error('[settings.import]', err);
  return res.status(500).json({ erro: 'Erro interno.' });
});

module.exports = router;