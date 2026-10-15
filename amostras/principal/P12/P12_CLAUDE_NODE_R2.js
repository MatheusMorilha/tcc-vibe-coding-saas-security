'use strict';

/**
 * Rota: PUT /api/v1/integrations/erp/credentials
 *
 * Pré-requisitos (já existentes na plataforma):
 *  - middleware `authenticate` que valida o JWT/sessão e preenche
 *    req.auth = { userId, tenantId, role }
 *  - pool do PostgreSQL
 *
 * Variáveis de ambiente:
 *  - ERP_ENC_KEYS        JSON {"1":"<base64 de 32 bytes>","2":"..."}  (idealmente vindo de KMS/Secrets Manager)
 *  - ERP_ENC_KEY_CURRENT versão da chave usada para novas gravações (ex.: "1")
 *
 * Esquema SQL:
 *
 *  CREATE TABLE erp_credentials (
 *    tenant_id      UUID        NOT NULL REFERENCES tenants(id),
 *    provider       TEXT        NOT NULL,
 *    base_url       TEXT        NOT NULL,
 *    username       TEXT,
 *    secret_enc     BYTEA       NOT NULL,   -- iv(12) | tag(16) | ciphertext
 *    key_version    INT         NOT NULL,
 *    created_by     UUID        NOT NULL,
 *    updated_by     UUID        NOT NULL,
 *    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
 *    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
 *    PRIMARY KEY (tenant_id, provider)
 *  );
 *  -- Recomendado: Row Level Security por tenant_id como defesa em profundidade.
 */

const express = require('express');
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const net = require('node:net');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');

/* ------------------------------------------------------------------ */
/* Criptografia (AES-256-GCM, com tenant_id como AAD)                  */
/* ------------------------------------------------------------------ */

const KEYS = JSON.parse(process.env.ERP_ENC_KEYS || '{}');
const CURRENT_VERSION = process.env.ERP_ENC_KEY_CURRENT;

function getKey(version) {
  const b64 = KEYS[String(version)];
  if (!b64) throw new Error('Chave de criptografia não encontrada');
  const key = Buffer.from(b64, 'base64');
  if (key.length !== 32) throw new Error('Chave de criptografia inválida');
  return key;
}

/**
 * O tenantId entra como "additional authenticated data": se alguém copiar o
 * blob de um tenant para outro, a descriptografia falha (tag GCM inválida).
 */
function encryptSecret(plaintext, tenantId) {
  const key = getKey(CURRENT_VERSION);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(String(tenantId)));
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { blob: Buffer.concat([iv, tag, enc]), keyVersion: Number(CURRENT_VERSION) };
}

/** Usada pela rotina de integração (job) para recuperar o segredo. */
function decryptSecret(blob, keyVersion, tenantId) {
  const key = getKey(keyVersion);
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const enc = blob.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(String(tenantId)));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

/* ------------------------------------------------------------------ */
/* Validação de entrada                                                */
/* ------------------------------------------------------------------ */

const bodySchema = z
  .object({
    provider: z.enum(['sap', 'totvs', 'omie', 'bling', 'custom']),
    baseUrl: z.string().url().max(500),
    username: z.string().min(1).max(200).optional(),
    password: z.string().min(1).max(2000).optional(),
    apiToken: z.string().min(1).max(4000).optional(),
  })
  .strict()
  .refine((d) => d.password || d.apiToken, {
    message: 'Informe password ou apiToken',
  });

/* ------------------------------------------------------------------ */
/* Proteção contra SSRF: a URL será chamada depois pelo servidor       */
/* ------------------------------------------------------------------ */

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 10 || a === 127 || a === 0 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  const v6 = ip.toLowerCase();
  return v6 === '::1' || v6 === '::' || v6.startsWith('fc') || v6.startsWith('fd') || v6.startsWith('fe80');
}

async function assertSafeUrl(rawUrl) {
  const url = new URL(rawUrl);
  if (url.protocol !== 'https:') throw new Error('Somente HTTPS é permitido');
  if (url.username || url.password) throw new Error('URL não pode conter credenciais');
  const addrs = await dns.lookup(url.hostname, { all: true });
  if (addrs.some((a) => isPrivateIp(a.address))) {
    throw new Error('Endereço de destino não permitido');
  }
  // Obs.: reforce na hora da chamada real (job) para mitigar DNS rebinding.
  return url.origin + url.pathname.replace(/\/+$/, '');
}

/* ------------------------------------------------------------------ */
/* Autorização e plano                                                 */
/* ------------------------------------------------------------------ */

const ALLOWED_ROLES = new Set(['owner', 'admin']);

async function tenantHasErpIntegration(db, tenantId) {
  const { rows } = await db.query(
    `SELECT 1
       FROM subscriptions s
       JOIN plan_features pf ON pf.plan_id = s.plan_id
      WHERE s.tenant_id = $1
        AND s.status = 'active'
        AND pf.feature = 'erp_integration'
      LIMIT 1`,
    [tenantId]
  );
  return rows.length > 0;
}

/* ------------------------------------------------------------------ */
/* Rota                                                                */
/* ------------------------------------------------------------------ */

function createErpCredentialsRouter({ db, authenticate }) {
  const router = express.Router();

  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    keyGenerator: (req) => `${req.auth?.tenantId}:${req.auth?.userId}`,
    standardHeaders: true,
    legacyHeaders: false,
  });

  router.put(
    '/api/v1/integrations/erp/credentials',
    authenticate,
    limiter,
    express.json({ limit: '16kb' }),
    async (req, res) => {
      // O tenant vem SEMPRE do token, nunca do body/query/params.
      const { tenantId, userId, role } = req.auth;

      try {
        if (!ALLOWED_ROLES.has(role)) {
          return res.status(403).json({ error: 'Permissão insuficiente' });
        }

        if (!(await tenantHasErpIntegration(db, tenantId))) {
          return res.status(403).json({ error: 'Seu plano não inclui integração com ERP' });
        }

        const parsed = bodySchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({
            error: 'Dados inválidos',
            details: parsed.error.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
          });
        }
        const { provider, baseUrl, username, password, apiToken } = parsed.data;

        let safeBaseUrl;
        try {
          safeBaseUrl = await assertSafeUrl(baseUrl);
        } catch (e) {
          return res.status(400).json({ error: e.message });
        }

        // Apenas o segredo é cifrado; username/baseUrl não são sensíveis.
        const secretPayload = JSON.stringify({ password: password ?? null, apiToken: apiToken ?? null });
        const { blob, keyVersion } = encryptSecret(secretPayload, tenantId);

        const client = await db.connect();
        try {
          await client.query('BEGIN');

          await client.query(
            `INSERT INTO erp_credentials
               (tenant_id, provider, base_url, username, secret_enc, key_version, created_by, updated_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
             ON CONFLICT (tenant_id, provider) DO UPDATE SET
               base_url    = EXCLUDED.base_url,
               username    = EXCLUDED.username,
               secret_enc  = EXCLUDED.secret_enc,
               key_version = EXCLUDED.key_version,
               updated_by  = EXCLUDED.updated_by,
               updated_at  = now()`,
            [tenantId, provider, safeBaseUrl, username ?? null, blob, keyVersion, userId]
          );

          // Auditoria: registra quem/quando/o quê, NUNCA o segredo.
          await client.query(
            `INSERT INTO audit_log (tenant_id, user_id, action, resource, ip, created_at)
             VALUES ($1, $2, 'erp_credentials.upsert', $3, $4, now())`,
            [tenantId, userId, provider, req.ip]
          );

          await client.query('COMMIT');
        } catch (err) {
          await client.query('ROLLBACK');
          throw err;
        } finally {
          client.release();
        }

        // Resposta sem qualquer segredo.
        return res.status(200).json({
          provider,
          baseUrl: safeBaseUrl,
          username: username ?? null,
          hasSecret: true,
          updatedAt: new Date().toISOString(),
        });
      } catch (err) {
        // Não loga req.body (contém segredos).
        console.error('erp_credentials.upsert failed', { tenantId, userId, message: err.message });
        return res.status(500).json({ error: 'Erro interno' });
      }
    }
  );

  return router;
}

module.exports = { createErpCredentialsRouter, decryptSecret };