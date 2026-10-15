'use strict';

/**
 * PUT /api/v1/account/logo
 * Body: { "url": "https://exemplo.com/logo.png" }
 *
 * Dependências: express, sharp, pg, express-rate-limit
 * Requer Node.js >= 18.
 */

const express = require('express');
const https = require('node:https');
const dns = require('node:dns');
const net = require('node:net');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const sharp = require('sharp');
const rateLimit = require('express-rate-limit');

const router = express.Router();

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------
const MAX_BYTES = 5 * 1024 * 1024;        // 5 MB
const MAX_REDIRECTS = 3;
const TOTAL_TIMEOUT_MS = 10_000;
const MAX_INPUT_PIXELS = 25_000_000;      // protege contra decompression bomb
const OUTPUT_SIZE = 512;                  // lado máximo do logotipo
const ALLOWED_FORMATS = new Set(['jpeg', 'png', 'webp']); // SVG fica de fora (XSS)
const STORAGE_ROOT = process.env.LOGO_STORAGE_ROOT || path.resolve('./storage');

// ---------------------------------------------------------------------------
// Proteção contra SSRF: bloqueio de faixas de IP internas/reservadas
// ---------------------------------------------------------------------------
const blocked = new net.BlockList();
[
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], // metadata de nuvem (AWS/GCP/Azure)
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
].forEach(([addr, bits]) => blocked.addSubnet(addr, bits, 'ipv4'));
[
  ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
].forEach(([addr, bits]) => blocked.addSubnet(addr, bits, 'ipv6'));

function isBlockedIp(ip) {
  const family = net.isIPv6(ip) ? 'ipv6' : 'ipv4';
  // IPv4 mapeado em IPv6 (::ffff:127.0.0.1)
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return blocked.check(mapped[1], 'ipv4');
  return blocked.check(ip, family);
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/**
 * lookup customizado: o IP validado é o MESMO usado na conexão,
 * o que elimina a janela de DNS rebinding (TOCTOU).
 */
function safeLookup(hostname, options, callback) {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const safe = addresses.filter((a) => !isBlockedIp(a.address));
    if (safe.length === 0 || safe.length !== addresses.length) {
      return callback(new HttpError(400, 'Destino da URL não permitido.'));
    }
    if (options && options.all) return callback(null, safe);
    return callback(null, safe[0].address, safe[0].family);
  });
}

function validateUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new HttpError(400, 'URL inválida.');
  }
  if (u.protocol !== 'https:') throw new HttpError(400, 'Apenas URLs https são aceitas.');
  if (u.username || u.password) throw new HttpError(400, 'URL com credenciais não é permitida.');
  if (u.port && u.port !== '443') throw new HttpError(400, 'Porta não permitida.');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  // IP literal não passa pelo lookup, então é validado aqui
  if (net.isIP(host) && isBlockedIp(host)) throw new HttpError(400, 'Destino da URL não permitido.');
  return u;
}

// ---------------------------------------------------------------------------
// Download com limite de tamanho, timeout e redirects validados a cada salto
// ---------------------------------------------------------------------------
function fetchOnce(url, signal) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      url,
      {
        method: 'GET',
        lookup: safeLookup,
        signal,
        headers: { 'User-Agent': 'SaaS-LogoFetcher/1.0', Accept: 'image/*' },
      },
      resolve
    );
    req.on('error', reject);
    req.end();
  });
}

async function downloadImage(rawUrl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TOTAL_TIMEOUT_MS);

  try {
    let url = validateUrl(rawUrl);

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const res = await fetchOnce(url, controller.signal);

      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        url = validateUrl(new URL(res.headers.location, url).toString());
        continue;
      }
      if (res.statusCode !== 200) {
        res.resume();
        throw new HttpError(422, `Não foi possível baixar a imagem (HTTP ${res.statusCode}).`);
      }

      const declared = Number(res.headers['content-length']);
      if (declared > MAX_BYTES) {
        res.destroy();
        throw new HttpError(413, 'Imagem excede o tamanho máximo de 5 MB.');
      }

      const chunks = [];
      let received = 0;
      for await (const chunk of res) {
        received += chunk.length;
        if (received > MAX_BYTES) {
          res.destroy();
          throw new HttpError(413, 'Imagem excede o tamanho máximo de 5 MB.');
        }
        chunks.push(chunk);
      }
      return Buffer.concat(chunks);
    }
    throw new HttpError(422, 'Redirecionamentos demais.');
  } catch (err) {
    if (err instanceof HttpError) throw err;
    if (err.name === 'AbortError' || err.code === 'ABORT_ERR') {
      throw new HttpError(504, 'Tempo esgotado ao baixar a imagem.');
    }
    if (err.cause instanceof HttpError) throw err.cause;
    throw new HttpError(422, 'Falha ao baixar a imagem.');
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Validação real do conteúdo + normalização (não confia em Content-Type/extensão)
// Reencodar remove metadados (EXIF) e qualquer payload embutido.
// ---------------------------------------------------------------------------
async function processImage(buffer) {
  try {
    const img = sharp(buffer, { limitInputPixels: MAX_INPUT_PIXELS, failOn: 'error' });
    const meta = await img.metadata();
    if (!ALLOWED_FORMATS.has(meta.format)) {
      throw new HttpError(415, 'Formato não suportado. Use PNG, JPEG ou WebP.');
    }
    return await img
      .rotate()
      .resize(OUTPUT_SIZE, OUTPUT_SIZE, { fit: 'inside', withoutEnlargement: true })
      .webp({ quality: 90 })
      .toBuffer();
  } catch (err) {
    if (err instanceof HttpError) throw err;
    throw new HttpError(422, 'Arquivo de imagem inválido ou corrompido.');
  }
}

// ---------------------------------------------------------------------------
// Storage (troque por S3/GCS em produção mantendo o prefixo por tenant)
// ---------------------------------------------------------------------------
const storage = {
  async put(key, buffer) {
    const full = path.join(STORAGE_ROOT, key);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, buffer, { flag: 'wx' });
  },
  async remove(key) {
    await fs.rm(path.join(STORAGE_ROOT, key), { force: true });
  },
};

// ---------------------------------------------------------------------------
// Middlewares (assumem que a autenticação já populou req.auth a partir do token)
//   req.auth = { userId, tenantId, role, plan }
// ---------------------------------------------------------------------------
function requireAdmin(req, res, next) {
  if (!req.auth || !req.auth.tenantId) return res.status(401).json({ error: 'Não autenticado.' });
  if (!['owner', 'admin'].includes(req.auth.role)) {
    return res.status(403).json({ error: 'Apenas administradores podem alterar o logotipo.' });
  }
  next();
}

// Limite por tenant (não por IP), evitando uso da rota como proxy de downloads
const logoLimiter = rateLimit({
  windowMs: 60_000,
  limit: 5,
  keyGenerator: (req) => `tenant:${req.auth.tenantId}`,
  standardHeaders: true,
  legacyHeaders: false,
});

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------
router.put(
  '/account/logo',
  requireAdmin,
  logoLimiter,
  express.json({ limit: '2kb' }),
  async (req, res, next) => {
    try {
      const { url } = req.body || {};
      if (typeof url !== 'string' || url.length === 0 || url.length > 2048) {
        throw new HttpError(400, 'Informe uma URL válida no campo "url".');
      }

      // O tenant vem EXCLUSIVAMENTE do token, nunca do body/query/params.
      const { tenantId } = req.auth;
      const db = req.app.get('db'); // pg.Pool

      // (Opcional) verifica se o plano permite personalização de marca
      const { rows: acc } = await db.query(
        'SELECT logo_key, plan_features FROM accounts WHERE id = $1',
        [tenantId]
      );
      if (acc.length === 0) throw new HttpError(404, 'Conta não encontrada.');
      if (acc[0].plan_features && acc[0].plan_features.custom_branding === false) {
        throw new HttpError(402, 'Seu plano atual não permite logotipo personalizado.');
      }

      const raw = await downloadImage(url);
      const processed = await processImage(raw);

      // Nome gerado pelo servidor: nenhuma parte vem do usuário (evita path traversal)
      const newKey = `tenants/${tenantId}/logo/${crypto.randomUUID()}.webp`;
      await storage.put(newKey, processed);

      try {
        // Filtro por id do tenant garante o isolamento na base compartilhada
        await db.query(
          'UPDATE accounts SET logo_key = $1, logo_updated_at = now() WHERE id = $2',
          [newKey, tenantId]
        );
      } catch (dbErr) {
        await storage.remove(newKey).catch(() => {});
        throw dbErr;
      }

      // Remove o logotipo anterior (best-effort)
      if (acc[0].logo_key) await storage.remove(acc[0].logo_key).catch(() => {});

      res.status(200).json({ message: 'Logotipo atualizado com sucesso.', logoKey: newKey });
    } catch (err) {
      next(err);
    }
  }
);

// Tratador de erros do módulo
router.use((err, req, res, next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  console.error('[logo] erro inesperado:', err);
  res.status(500).json({ error: 'Erro interno.' });
});

module.exports = router;