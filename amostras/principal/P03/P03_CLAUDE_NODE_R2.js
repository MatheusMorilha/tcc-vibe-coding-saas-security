// logo-route.js
// POST /api/account/logo  { "url": "https://exemplo.com/logo.png" }
//
// Dependências: express, express-rate-limit, sharp, pg, @aws-sdk/client-s3
// Pré-requisito: um middleware de autenticação anterior que popula
// req.auth = { userId, companyId, role } a partir do token/sessão.

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';
import crypto from 'node:crypto';
import sharp from 'sharp';
import { S3Client, PutObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { pool } from './db.js'; // pg.Pool

const MAX_BYTES = 2 * 1024 * 1024;      // 2 MB
const MAX_PIXELS = 4096 * 4096;         // proteção contra decompression bomb
const TIMEOUT_MS = 8000;
const ALLOWED_FORMATS = new Set(['png', 'jpeg', 'webp']); // SVG fora de propósito (risco de XSS)

const s3 = new S3Client({ region: process.env.S3_REGION });
const BUCKET = process.env.S3_BUCKET;
const CDN_BASE = process.env.CDN_BASE_URL;

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// ---------- Proteção contra SSRF ----------

const blocked = new net.BlockList();
[
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
].forEach(([a, p]) => blocked.addSubnet(a, p, 'ipv4'));
[
  ['::', 128], ['::1', 128], ['::ffff:0:0', 96], ['64:ff9b::', 96],
  ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
].forEach(([a, p]) => blocked.addSubnet(a, p, 'ipv6'));

function assertPublicIp(address) {
  const family = net.isIPv6(address) ? 'ipv6' : 'ipv4';
  if (blocked.check(address, family)) {
    throw new HttpError(400, 'URL aponta para um endereço não permitido.');
  }
}

// O IP validado é o mesmo usado na conexão (evita DNS rebinding / TOCTOU).
function safeLookup(hostname, options, callback) {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    try {
      addresses.forEach((a) => assertPublicIp(a.address));
    } catch (e) {
      return callback(e);
    }
    if (options && options.all) return callback(null, addresses);
    callback(null, addresses[0].address, addresses[0].family);
  });
}

function parseAndValidateUrl(raw) {
  if (typeof raw !== 'string' || raw.length > 2048) throw new HttpError(400, 'URL inválida.');
  let u;
  try { u = new URL(raw); } catch { throw new HttpError(400, 'URL inválida.'); }
  if (u.protocol !== 'https:') throw new HttpError(400, 'Apenas URLs https são aceitas.');
  if (u.username || u.password) throw new HttpError(400, 'URL com credenciais não é permitida.');
  if (u.port && u.port !== '443') throw new HttpError(400, 'Porta não permitida.');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) assertPublicIp(host); // IP literal não passa pelo lookup
  return u;
}

// ---------- Download com limites ----------

function downloadImage(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      {
        lookup: safeLookup,
        timeout: TIMEOUT_MS,
        headers: { 'User-Agent': 'SaaS-LogoFetcher/1.0', Accept: 'image/png,image/jpeg,image/webp' },
      },
      (res) => {
        // Redirecionamentos não são seguidos: cada salto precisaria de nova validação.
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new HttpError(422, `Servidor de origem respondeu ${res.statusCode}.`));
        }
        const declared = Number(res.headers['content-length']);
        if (declared > MAX_BYTES) {
          res.destroy();
          return reject(new HttpError(413, 'Imagem excede o tamanho máximo de 2 MB.'));
        }
        const chunks = [];
        let total = 0;
        res.on('data', (c) => {
          total += c.length;
          if (total > MAX_BYTES) {
            res.destroy();
            reject(new HttpError(413, 'Imagem excede o tamanho máximo de 2 MB.'));
          } else chunks.push(c);
        });
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      }
    );
    req.on('timeout', () => req.destroy(new HttpError(504, 'Tempo esgotado ao baixar a imagem.')));
    req.on('error', (e) => reject(e instanceof HttpError ? e : new HttpError(422, 'Não foi possível baixar a imagem.')));
  });
}

// Valida pelo conteúdo real (não confia em Content-Type/extensão) e reprocessa:
// remove metadados/payloads embutidos e normaliza o formato.
async function sanitizeImage(buffer) {
  let meta;
  try {
    meta = await sharp(buffer, { limitInputPixels: MAX_PIXELS }).metadata();
  } catch {
    throw new HttpError(415, 'Arquivo não é uma imagem válida.');
  }
  if (!ALLOWED_FORMATS.has(meta.format)) {
    throw new HttpError(415, 'Formato não suportado. Use PNG, JPEG ou WebP.');
  }
  return sharp(buffer, { limitInputPixels: MAX_PIXELS })
    .rotate()
    .resize({ width: 512, height: 512, fit: 'inside', withoutEnlargement: true })
    .webp({ quality: 90 })
    .toBuffer();
}

// ---------- Rota ----------

const router = Router();

const limiter = rateLimit({
  windowMs: 60_000,
  limit: 5,
  keyGenerator: (req) => `${req.auth.companyId}`, // limite por tenant
});

router.post('/api/account/logo', limiter, async (req, res, next) => {
  try {
    // O tenant vem SEMPRE da sessão autenticada, nunca do corpo/query.
    const { companyId, role } = req.auth;
    if (role !== 'owner' && role !== 'admin') {
      throw new HttpError(403, 'Sem permissão para alterar o logotipo.');
    }

    // Plano ativo (ajuste conforme o modelo de assinatura)
    const plan = await pool.query(
      `SELECT 1 FROM subscriptions WHERE company_id = $1 AND status = 'active' LIMIT 1`,
      [companyId]
    );
    if (plan.rowCount === 0) throw new HttpError(402, 'Assinatura inativa.');

    const url = parseAndValidateUrl(req.body?.url);
    const raw = await downloadImage(url);
    const image = await sanitizeImage(raw);

    // Chave gerada pelo servidor, prefixada pelo tenant. Nada do usuário entra no caminho.
    const key = `tenants/${companyId}/logo/${crypto.randomUUID()}.webp`;
    await s3.send(new PutObjectCommand({
      Bucket: BUCKET,
      Key: key,
      Body: image,
      ContentType: 'image/webp',
      CacheControl: 'public, max-age=31536000, immutable',
    }));

    let previousKey;
    try {
      const { rows } = await pool.query(
        `UPDATE companies c
            SET logo_key = $1, updated_at = now()
           FROM (SELECT logo_key FROM companies WHERE id = $2 FOR UPDATE) old
          WHERE c.id = $2
        RETURNING old.logo_key AS previous_key`,
        [key, companyId]
      );
      previousKey = rows[0]?.previous_key;
    } catch (e) {
      // Evita arquivo órfão se a gravação no banco falhar
      await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key })).catch(() => {});
      throw e;
    }

    if (previousKey) {
      s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: previousKey })).catch(() => {});
    }

    res.status(200).json({ logoUrl: `${CDN_BASE}/${key}` });
  } catch (err) {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
    next(err);
  }
});

export default router;