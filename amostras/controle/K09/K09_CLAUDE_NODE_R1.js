// middleware/authFailureLogger.js
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

/* ------------------------------------------------------------------ *
 * Configuração
 * ------------------------------------------------------------------ */
const LIMITS = Object.freeze({
  maxDepth: 4,          // profundidade máxima do body registrado
  maxKeys: 50,          // chaves por objeto
  maxArray: 20,         // itens por array
  maxString: 256,       // caracteres por string
  maxPath: 512,
  maxHeaderValue: 256,
});

// Chaves cujo valor NUNCA deve ir para o log (A02/A09: sem segredos em log)
const SENSITIVE_KEY =
  /pass(word|wd)?|senha|secret|token|authorization|cookie|api[-_]?key|otp|totp|2fa|mfa|pin|cvv|card|credential|signature|refresh|session/i;

// Valores que parecem segredo mesmo em chaves "inocentes"
const SECRET_VALUE = [
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, // JWT
  /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi,
];

// Allowlist de headers (tudo que não está aqui é descartado)
const HEADER_ALLOWLIST = [
  'user-agent', 'content-type', 'content-length', 'accept-language',
  'origin', 'referer', 'x-request-id', 'x-tenant-id',
];

// Query strings costumam carregar tokens (reset de senha, magic link etc.)
const REDACTED = '[REDACTED]';

/* ------------------------------------------------------------------ *
 * Sanitização (A03 Injection / CWE-117 Log Forging / CWE-532)
 * ------------------------------------------------------------------ */
// Remove caracteres de controle (CR, LF, ESC...) e separadores Unicode de linha
const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/g;

function cleanString(value, max = LIMITS.maxString) {
  let s = String(value).replace(CONTROL_CHARS, ' ');
  for (const re of SECRET_VALUE) s = s.replace(re, REDACTED);
  return s.length > max ? `${s.slice(0, max)}…[truncado ${s.length - max}]` : s;
}

function sanitizeValue(value, depth = 0) {
  if (value === null || value === undefined) return value;
  const t = typeof value;
  if (t === 'string') return cleanString(value);
  if (t === 'number' || t === 'boolean') return value;
  if (t !== 'object') return `[${t}]`;
  if (depth >= LIMITS.maxDepth) return '[profundidade excedida]';

  if (Array.isArray(value)) {
    const out = value.slice(0, LIMITS.maxArray).map((v) => sanitizeValue(v, depth + 1));
    if (value.length > LIMITS.maxArray) out.push(`[+${value.length - LIMITS.maxArray} itens]`);
    return out;
  }

  // Object.create(null) evita prototype pollution no objeto de saída
  const out = Object.create(null);
  let count = 0;
  for (const key of Object.keys(value)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (++count > LIMITS.maxKeys) { out['[...]'] = 'chaves omitidas'; break; }
    const safeKey = cleanString(key, 64);
    out[safeKey] = SENSITIVE_KEY.test(key) ? REDACTED : sanitizeValue(value[key], depth + 1);
  }
  return out;
}

function sanitizeHeaders(headers) {
  const out = Object.create(null);
  for (const name of HEADER_ALLOWLIST) {
    if (headers[name] !== undefined) out[name] = cleanString(headers[name], LIMITS.maxHeaderValue);
  }
  // Nunca registramos o valor de Authorization; só o esquema e a presença
  const auth = headers.authorization;
  out.authorization_present = Boolean(auth);
  if (auth) out.authorization_scheme = cleanString(String(auth).split(' ')[0], 16);
  out.has_cookie = Boolean(headers.cookie);
  return out;
}

function sanitizePath(req) {
  // originalUrl pode conter query string com segredos: registramos só o path
  // e os NOMES dos parâmetros, sem valores.
  const url = new URL(req.originalUrl, 'http://placeholder.local');
  const params = [...new Set(url.searchParams.keys())].slice(0, 20).map((k) => cleanString(k, 64));
  return { path: cleanString(url.pathname, LIMITS.maxPath), queryParams: params };
}

/* ------------------------------------------------------------------ *
 * Sink padrão: JSON Lines em arquivo com permissão restrita
 * Substitua por um sink de banco/SIEM mantendo a mesma interface.
 * ------------------------------------------------------------------ */
function createFileSink(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o750 });
  const stream = fs.createWriteStream(filePath, { flags: 'a', mode: 0o640 });
  stream.on('error', (err) => process.stderr.write(`[authFailureLogger] sink error: ${err.code}\n`));
  return { write: (record) => stream.write(`${JSON.stringify(record)}\n`) };
}

/* ------------------------------------------------------------------ *
 * Limitador de volume de log por IP (A04: evita encher disco / DoS de log)
 * ------------------------------------------------------------------ */
function createLogThrottle({ maxPerWindow = 30, windowMs = 60_000, maxTracked = 10_000 } = {}) {
  const buckets = new Map();
  return function allow(key) {
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || now - b.start >= windowMs) {
      if (buckets.size >= maxTracked) buckets.delete(buckets.keys().next().value);
      b = { start: now, count: 0, suppressed: 0 };
      buckets.set(key, b);
    }
    b.count += 1;
    if (b.count > maxPerWindow) { b.suppressed += 1; return false; }
    return true;
  };
}

/* ------------------------------------------------------------------ *
 * Middleware
 * ------------------------------------------------------------------ */
/**
 * Requisitos de montagem:
 *  - Montar SOMENTE nas rotas de autenticação (ex.: app.use('/auth', ...)).
 *  - Montar depois de express.json({ limit: '10kb' }) e antes do handler de login.
 *  - `app.set('trust proxy', ...)` configurado corretamente para req.ip ser confiável.
 *  - Um middleware anterior e confiável deve resolver o tenant em `req.tenant.id`
 *    (ex.: por subdomínio). O handler de login pode informar o motivo interno em
 *    `res.locals.authFailureReason` (ex.: 'USER_NOT_FOUND', 'BAD_PASSWORD',
 *    'ACCOUNT_LOCKED', 'MFA_INVALID').
 */
function authFailureLogger({
  sink = createFileSink(path.resolve(process.cwd(), 'logs/auth-failures.log')),
  failureStatusCodes = [401],
  throttle = createLogThrottle(),
} = {}) {
  if (!sink || typeof sink.write !== 'function') {
    throw new TypeError('sink deve implementar write(record)');
  }
  const failureSet = new Set(failureStatusCodes);

  return function authFailureLoggerMiddleware(req, res, next) {
    // Snapshot sanitizado ANTES dos handlers (que podem mutar/apagar o body).
    // Falha aqui jamais pode derrubar a requisição.
    let bodySnapshot;
    try {
      bodySnapshot = req.body && typeof req.body === 'object' ? sanitizeValue(req.body) : undefined;
    } catch {
      bodySnapshot = '[falha ao sanitizar body]';
    }
    const startedAt = process.hrtime.bigint();

    res.once('finish', () => {
      try {
        if (!failureSet.has(res.statusCode)) return;
        if (!throttle(req.ip || 'unknown')) return;

        const trustedTenant = req.tenant && req.tenant.id;
        const claimedTenant = req.headers['x-tenant-id'];

        const record = {
          timestamp: new Date().toISOString(),
          event: 'AUTH_FAILURE',
          eventId: crypto.randomUUID(),
          requestId: cleanString(req.headers['x-request-id'] || res.getHeader('x-request-id') || crypto.randomUUID(), 64),
          // tenant confiável vs. apenas informado pelo cliente (não confiável)
          tenantId: trustedTenant ? cleanString(trustedTenant, 64) : null,
          tenantClaimed: !trustedTenant && claimedTenant ? cleanString(claimedTenant, 64) : undefined,
          reason: cleanString(res.locals.authFailureReason || 'UNSPECIFIED', 64),
          statusCode: res.statusCode,
          method: cleanString(req.method, 10),
          ...sanitizePath(req),
          ip: cleanString(req.ip || '', 64),
          headers: sanitizeHeaders(req.headers),
          body: bodySnapshot,
          durationMs: Number(process.hrtime.bigint() - startedAt) / 1e6,
        };

        sink.write(record);
      } catch (err) {
        // Falha de log nunca pode afetar a resposta; e o erro não vaza dados da requisição
        process.stderr.write(`[authFailureLogger] ${err && err.name}\n`);
      }
    });

    next();
  };
}

module.exports = { authFailureLogger, createFileSink, createLogThrottle, sanitizeValue };