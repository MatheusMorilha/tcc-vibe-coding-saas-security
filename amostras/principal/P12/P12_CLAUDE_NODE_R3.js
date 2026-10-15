// ============================================================
// erp-credentials.routes.js
// PUT /api/v1/integrations/erp/credentials
// Dependências: express, zod, pg, express-rate-limit
// ============================================================
'use strict';

const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const net = require('node:net');
const express = require('express');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

/*
-- SQL (migração)
CREATE TABLE erp_credentials (
  company_id     UUID PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
  erp_type       TEXT        NOT NULL,
  base_url       TEXT        NOT NULL,
  secret_enc     BYTEA       NOT NULL,   -- ciphertext AES-256-GCM
  secret_iv      BYTEA       NOT NULL,
  secret_tag     BYTEA       NOT NULL,
  key_version    INTEGER     NOT NULL,
  updated_by     UUID        NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Recomendado: Row Level Security por company_id como defesa em profundidade.

CREATE TABLE audit_log (
  id          BIGSERIAL PRIMARY KEY,
  company_id  UUID NOT NULL,
  user_id     UUID NOT NULL,
  action      TEXT NOT NULL,
  ip          INET,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
*/

// ------------------------------------------------------------
// 1. Criptografia (AES-256-GCM, AAD vinculado ao tenant)
// ------------------------------------------------------------
// ERP_CRED_KEYS='{"1":"<base64 de 32 bytes>"}'  (idealmente vindo de KMS/Vault)
// ERP_CRED_KEY_VERSION=1
const KEYS = JSON.parse(process.env.ERP_CRED_KEYS || '{}');
const CURRENT_KEY_VERSION = Number(process.env.ERP_CRED_KEY_VERSION);

function getKey(version) {
  const raw = KEYS[version];
  if (!raw) throw new Error(`Chave de criptografia v${version} não configurada`);
  const key = Buffer.from(raw, 'base64');
  if (key.length !== 32) throw new Error('A chave deve ter 32 bytes');
  return key;
}

function encryptSecret(plainObject, companyId) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(CURRENT_KEY_VERSION), iv);
  // AAD: o ciphertext só decifra para a empresa dona dele
  cipher.setAAD(Buffer.from(companyId));
  const enc = Buffer.concat([cipher.update(JSON.stringify(plainObject), 'utf8'), cipher.final()]);
  return { enc, iv, tag: cipher.getAuthTag(), keyVersion: CURRENT_KEY_VERSION };
}

// Usada pela rotina de integração (worker) para recuperar as credenciais
function decryptSecret({ secret_enc, secret_iv, secret_tag, key_version }, companyId) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(key_version), secret_iv);
  decipher.setAAD(Buffer.from(companyId));
  decipher.setAuthTag(secret_tag);
  const dec = Buffer.concat([decipher.update(secret_enc), decipher.final()]);
  return JSON.parse(dec.toString('utf8'));
}

// ------------------------------------------------------------
// 2. Validação de entrada e proteção contra SSRF
// ------------------------------------------------------------
const blocked = new net.BlockList();
[
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.168.0.0', 16],
].forEach(([ip, p]) => blocked.addSubnet(ip, p, 'ipv4'));
blocked.addSubnet('::1', 128, 'ipv6');
blocked.addSubnet('fc00::', 7, 'ipv6');
blocked.addSubnet('fe80::', 10, 'ipv6');

async function assertPublicHost(hostname) {
  const addrs = await dns.lookup(hostname, { all: true });
  for (const { address, family } of addrs) {
    if (blocked.check(address, family === 6 ? 'ipv6' : 'ipv4')) {
      throw new Error('Host não permitido');
    }
  }
}

const bodySchema = z
  .object({
    erpType: z.enum(['sap', 'totvs', 'oracle', 'omie', 'bling', 'custom']),
    baseUrl: z
      .string()
      .url()
      .max(2048)
      .refine((u) => new URL(u).protocol === 'https:', 'Somente HTTPS é permitido'),
    authType: z.enum(['api_key', 'basic', 'oauth_client_credentials']),
    apiKey: z.string().min(8).max(4096).optional(),
    username: z.string().min(1).max(256).optional(),
    password: z.string().min(1).max(1024).optional(),
    clientId: z.string().min(1).max(512).optional(),
    clientSecret: z.string().min(1).max(2048).optional(),
  })
  .strict() // rejeita campos extras (ex.: tentativa de enviar companyId)
  .superRefine((d, ctx) => {
    const need = {
      api_key: ['apiKey'],
      basic: ['username', 'password'],
      oauth_client_credentials: ['clientId', 'clientSecret'],
    }[d.authType];
    for (const f of need) {
      if (!d[f]) ctx.addIssue({ code: 'custom', path: [f], message: `Obrigatório para ${d.authType}` });
    }
  });

// ------------------------------------------------------------
// 3. Middlewares de autorização (contrato esperado)
// ------------------------------------------------------------
// authenticate: valida o JWT/sessão e define req.auth = { userId, companyId, role }
// requireActivePlan(feature): verifica assinatura ativa e se o plano inclui a feature
// Ambos são fornecidos pela aplicação.
function requireRole(...roles) {
  return (req, res, next) =>
    roles.includes(req.auth?.role) ? next() : res.status(403).json({ error: 'Acesso negado' });
}

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  keyGenerator: (req) => req.auth.companyId, // limite por empresa
  standardHeaders: true,
  legacyHeaders: false,
});

// ------------------------------------------------------------
// 4. Rota
// ------------------------------------------------------------
module.exports = function buildErpCredentialsRouter({ db, authenticate, requireActivePlan }) {
  const router = express.Router();

  router.put(
    '/api/v1/integrations/erp/credentials',
    express.json({ limit: '16kb' }),
    authenticate,
    requireRole('owner', 'admin'),
    requireActivePlan('erp_integration'),
    limiter,
    async (req, res) => {
      // O tenant vem EXCLUSIVAMENTE do token autenticado, nunca do corpo/URL
      const { companyId, userId } = req.auth;

      const parsed = bodySchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(422).json({
          error: 'Dados inválidos',
          details: parsed.error.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
        });
      }
      const { erpType, baseUrl, authType, ...secrets } = parsed.data;

      try {
        await assertPublicHost(new URL(baseUrl).hostname);
      } catch {
        return res.status(422).json({ error: 'URL do ERP inválida ou não permitida' });
      }

      // Apenas os campos secretos são cifrados; nada é logado
      const secretPayload = { authType, ...secrets };
      const { enc, iv, tag, keyVersion } = encryptSecret(secretPayload, companyId);

      const client = await db.connect();
      try {
        await client.query('BEGIN');
        await client.query(
          `INSERT INTO erp_credentials
             (company_id, erp_type, base_url, secret_enc, secret_iv, secret_tag, key_version, updated_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
           ON CONFLICT (company_id) DO UPDATE SET
             erp_type    = EXCLUDED.erp_type,
             base_url    = EXCLUDED.base_url,
             secret_enc  = EXCLUDED.secret_enc,
             secret_iv   = EXCLUDED.secret_iv,
             secret_tag  = EXCLUDED.secret_tag,
             key_version = EXCLUDED.key_version,
             updated_by  = EXCLUDED.updated_by,
             updated_at  = now()`,
          [companyId, erpType, baseUrl, enc, iv, tag, keyVersion, userId]
        );
        await client.query(
          `INSERT INTO audit_log (company_id, user_id, action, ip)
           VALUES ($1,$2,'erp_credentials.upsert',$3)`,
          [companyId, userId, req.ip]
        );
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        // Loga apenas a mensagem de erro, jamais req.body
        console.error('[erp-credentials] falha ao salvar', { companyId, code: err.code });
        return res.status(500).json({ error: 'Não foi possível salvar as credenciais' });
      } finally {
        client.release();
      }

      // Resposta sem qualquer segredo
      res.set('Cache-Control', 'no-store');
      return res.status(200).json({
        erpType,
        baseUrl,
        authType,
        configured: true,
        updatedAt: new Date().toISOString(),
      });
    }
  );

  return router;
};

module.exports.decryptSecret = decryptSecret;