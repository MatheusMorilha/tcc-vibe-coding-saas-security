const dns = require('dns').promises;
const net = require('net');
const https = require('https');
const http = require('http');
const { URL } = require('url');

// ---- Configurações de segurança ----
const ALLOWED_PROTOCOLS = ['https:', 'http:'];
const ALLOWED_CONTENT_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/webp',
  'image/gif',
]);
const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5MB
const DOWNLOAD_TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 3;

class InvalidLogoUrlError extends Error {}
class LogoDownloadError extends Error {}

/**
 * Verifica se um endereço IP é privado/reservado/loopback.
 * Cobre IPv4 e IPv6.
 */
function isPrivateOrReservedIp(ip) {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;

    if (a === 127) return true; // loopback
    if (a === 10) return true; // classe privada
    if (a === 172 && b >= 16 && b <= 31) return true; // classe privada
    if (a === 192 && b === 168) return true; // classe privada
    if (a === 169 && b === 254) return true; // link-local (inclui metadata cloud)
    if (a === 0) return true; // "this network"
    if (a >= 224) return true; // multicast/reservado
    return false;
  }

  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1') return true; // loopback
    if (lower.startsWith('fe80:')) return true; // link-local
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique local (fc00::/7)
    if (lower.startsWith('::ffff:')) {
      // IPv4-mapped IPv6 — valida a parte IPv4
      const ipv4Part = lower.split(':').pop();
      if (net.isIPv4(ipv4Part)) return isPrivateOrReservedIp(ipv4Part);
    }
    return false;
  }

  // Se não reconhecemos o formato, tratamos como não seguro por padrão
  return true;
}

/**
 * Valida a URL informada e resolve o hostname, garantindo que não aponta
 * para nenhum host interno/privado antes de fazer qualquer requisição.
 */
async function validateAndResolveUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new InvalidLogoUrlError('URL inválida.');
  }

  if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
    throw new InvalidLogoUrlError('Protocolo não permitido. Use http ou https.');
  }

  if (parsed.username || parsed.password) {
    throw new InvalidLogoUrlError('URL não pode conter credenciais.');
  }

  // Bloqueia hostnames óbvios de rede interna
  const hostname = parsed.hostname.toLowerCase();
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal')
  ) {
    throw new InvalidLogoUrlError('Host não permitido.');
  }

  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch {
    throw new InvalidLogoUrlError('Não foi possível resolver o host.');
  }

  if (addresses.length === 0) {
    throw new InvalidLogoUrlError('Host sem endereço resolvível.');
  }

  for (const { address } of addresses) {
    if (isPrivateOrReservedIp(address)) {
      throw new InvalidLogoUrlError('URL aponta para um endereço de rede não permitido.');
    }
  }

  return { parsed, resolvedIp: addresses[0].address };
}

/**
 * Baixa o conteúdo de uma URL já validada, aplicando timeout,
 * limite de tamanho, validação de content-type e número máximo
 * de redirecionamentos (revalidando cada salto).
 */
async function downloadImage(rawUrl, redirectsLeft = MAX_REDIRECTS) {
  const { parsed } = await validateAndResolveUrl(rawUrl);
  const client = parsed.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const request = client.get(
      parsed,
      {
        timeout: DOWNLOAD_TIMEOUT_MS,
        headers: { 'User-Agent': 'SaaS-LogoFetcher/1.0' },
      },
      (response) => {
        // Trata redirecionamentos manualmente para revalidar cada URL de destino
        if (
          [301, 302, 303, 307, 308].includes(response.statusCode) &&
          response.headers.location
        ) {
          response.resume(); // descarta o corpo
          if (redirectsLeft <= 0) {
            reject(new LogoDownloadError('Número máximo de redirecionamentos excedido.'));
            return;
          }
          const nextUrl = new URL(response.headers.location, parsed).toString();
          downloadImage(nextUrl, redirectsLeft - 1).then(resolve).catch(reject);
          return;
        }

        if (response.statusCode !== 200) {
          response.resume();
          reject(new LogoDownloadError(`Falha ao baixar imagem. Status: ${response.statusCode}`));
          return;
        }

        const contentType = (response.headers['content-type'] || '').split(';')[0].trim();
        if (!ALLOWED_CONTENT_TYPES.has(contentType)) {
          response.resume();
          reject(new LogoDownloadError(`Tipo de conteúdo não permitido: ${contentType}`));
          return;
        }

        const contentLength = Number(response.headers['content-length']);
        if (contentLength && contentLength > MAX_FILE_SIZE_BYTES) {
          response.resume();
          reject(new LogoDownloadError('Arquivo excede o tamanho máximo permitido.'));
          return;
        }

        const chunks = [];
        let totalSize = 0;

        response.on('data', (chunk) => {
          totalSize += chunk.length;
          if (totalSize > MAX_FILE_SIZE_BYTES) {
            request.destroy();
            reject(new LogoDownloadError('Arquivo excede o tamanho máximo permitido.'));
            return;
          }
          chunks.push(chunk);
        });

        response.on('end', () => {
          resolve({
            buffer: Buffer.concat(chunks),
            contentType,
          });
        });

        response.on('error', (err) => reject(new LogoDownloadError(err.message)));
      }
    );

    request.on('timeout', () => {
      request.destroy();
      reject(new LogoDownloadError('Tempo limite de download excedido.'));
    });

    request.on('error', (err) => reject(new LogoDownloadError(err.message)));
  });
}

module.exports = {
  downloadImage,
  validateAndResolveUrl,
  InvalidLogoUrlError,
  LogoDownloadError,
  ALLOWED_CONTENT_TYPES,
  MAX_FILE_SIZE_BYTES,
};

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

// Em produção, troque esta implementação por um adapter para S3/GCS/Azure Blob.
// O ponto importante é: o caminho/øchave de armazenamento é sempre derivado do
// tenantId autenticado (nunca de input do cliente), evitando path traversal
// e vazamento de dados entre empresas.

const STORAGE_ROOT = path.resolve(process.env.LOGO_STORAGE_PATH || './storage/logos');

const EXTENSION_BY_CONTENT_TYPE = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/webp': 'webp',
  'image/gif': 'gif',
};

async function saveTenantLogo({ tenantId, buffer, contentType }) {
  if (!tenantId || typeof tenantId !== 'string') {
    throw new Error('tenantId inválido para armazenamento.');
  }

  const extension = EXTENSION_BY_CONTENT_TYPE[contentType];
  if (!extension) {
    throw new Error('Tipo de conteúdo sem extensão mapeada.');
  }

  const tenantDir = path.join(STORAGE_ROOT, tenantId);
  await fs.mkdir(tenantDir, { recursive: true });

  // Nome de arquivo gerado pelo servidor (não vem do cliente)
  const fileName = `logo-${crypto.randomUUID()}.${extension}`;
  const filePath = path.join(tenantDir, fileName);

  await fs.writeFile(filePath, buffer);

  // Retorne aqui a URL pública/assinada conforme sua infraestrutura real
  const publicUrl = `/static/logos/${tenantId}/${fileName}`;

  return { filePath, publicUrl, fileName };
}

module.exports = { saveTenantLogo };

const {
  downloadImage,
  InvalidLogoUrlError,
  LogoDownloadError,
} = require('../services/logoDownload.service');
const { saveTenantLogo } = require('../storage/fileStorage');
const db = require('../db'); // assume um módulo de acesso a dados já existente

/**
 * POST /api/account/logo
 * Body: { imageUrl: string }
 *
 * Importante (multi-tenant): o tenantId NUNCA vem do body/query da requisição.
 * Ele é extraído exclusivamente do contexto de autenticação (req.auth),
 * já validado pelo middleware de auth, para impedir que uma empresa
 * altere o logo de outra.
 */
async function uploadLogoFromUrl(req, res) {
  const tenantId = req.auth?.tenantId;
  const userId = req.auth?.userId;

  if (!tenantId || !userId) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }

  const { imageUrl } = req.body || {};
  if (!imageUrl || typeof imageUrl !== 'string') {
    return res.status(400).json({ error: 'Campo "imageUrl" é obrigatório e deve ser uma string.' });
  }

  try {
    const { buffer, contentType } = await downloadImage(imageUrl);

    const { publicUrl } = await saveTenantLogo({
      tenantId,
      buffer,
      contentType,
    });

    // Atualiza apenas o registro da própria empresa (tenantId vindo do auth)
    await db.companies.update(
      { id: tenantId },
      { logoUrl: publicUrl, logoUpdatedAt: new Date(), logoUpdatedBy: userId }
    );

    return res.status(200).json({
      message: 'Logotipo atualizado com sucesso.',
      logoUrl: publicUrl,
    });
  } catch (err) {
    if (err instanceof InvalidLogoUrlError) {
      return res.status(400).json({ error: err.message });
    }
    if (err instanceof LogoDownloadError) {
      return res.status(422).json({ error: err.message });
    }

    // eslint-disable-next-line no-console
    console.error('Erro inesperado ao processar logo:', err);
    return res.status(500).json({ error: 'Erro interno ao processar a imagem.' });
  }
}

module.exports = { uploadLogoFromUrl };

const express = require('express');
const rateLimit = require('express-rate-limit'); // npm install express-rate-limit

const { uploadLogoFromUrl } = require('../controllers/logo.controller');
const { authenticate } = require('../middlewares/auth'); // já existente na aplicação

const router = express.Router();

// Limita a taxa de chamadas para reduzir abuso da rota como vetor de
// varredura de rede interna (SSRF) ou de negação de serviço via downloads.
const logoUploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

router.post(
  '/api/account/logo',
  authenticate, // garante req.auth.tenantId / req.auth.userId
  logoUploadLimiter,
  uploadLogoFromUrl
);

module.exports = router;