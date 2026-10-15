'use strict';

/**
 * requestLogger.js
 *
 * Middleware de log de requisições para API SaaS multilocatária.
 * - Uma entrada de log por requisição (gravada ao final, com status e duração).
 * - Contexto lido de forma "lazy" (no fim da resposta): funciona mesmo montado
 *   antes da autenticação e do body parser, e registra também requisições
 *   rejeitadas (401/403/400).
 * - Redação de dados sensíveis (credenciais, tokens, cartões, documentos).
 * - Limites de tamanho, profundidade e tipo de conteúdo.
 * - Falha no log NUNCA derruba a requisição.
 */

const { randomUUID } = require('node:crypto');

const REDACTED = '[REDACTED]';

// Chaves cujo valor é removido por completo (credenciais e segredos).
const SECRET_KEY_RE =
  /(pass(word|wd)?|senha|secret|token|authorization|cookie|api[-_]?key|private[-_]?key|card[-_]?number|numero[-_]?cartao|cvv|cvc|otp)/i;

// Chaves com dado pessoal: mascaradas parcialmente (LGPD), mantendo os
// últimos 2 caracteres para o suporte conseguir correlacionar.
const PII_KEY_RE = /(cpf|cnpj|rg|ssn|documento)/i;

const SENSITIVE_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-csrf-token',
]);

const LOGGABLE_CONTENT_TYPES = [
  'application/json',
  'application/x-www-form-urlencoded',
  'application/xml',
  'text/plain',
];

const DEFAULT_OPTIONS = {
  // Logger compatível com pino/winston: precisa ter .info() e .error().
  logger: console,
  maxBodyBytes: 16 * 1024, // acima disso o corpo é descartado (só metadados)
  maxStringLength: 1024, // strings maiores são truncadas
  maxArrayLength: 50, // arrays maiores são truncados
  maxDepth: 8, // profundidade máxima de objetos aninhados
  ignorePaths: ['/health', '/healthz', '/ready', '/metrics'],
  // Extrai tenant/usuário. Ajuste conforme o seu middleware de autenticação.
  getContext: (req) => ({
    tenantId: req.auth?.tenantId ?? req.user?.tenantId ?? req.tenant?.id ?? null,
    userId: req.auth?.userId ?? req.user?.id ?? null,
  }),
};

function maskPartial(value) {
  const s = String(value);
  if (s.length <= 4) return REDACTED;
  return '*'.repeat(s.length - 2) + s.slice(-2);
}

/** Copia o valor aplicando redação, limites e proteção contra referência circular. */
function sanitize(value, opts, depth = 0, seen = new WeakSet()) {
  if (value === null || value === undefined) return value;

  if (typeof value === 'string') {
    return value.length > opts.maxStringLength
      ? `${value.slice(0, opts.maxStringLength)}…[truncated ${value.length - opts.maxStringLength} chars]`
      : value;
  }
  if (typeof value !== 'object') return value; // number, boolean
  if (Buffer.isBuffer(value)) return `[Buffer ${value.length} bytes]`;

  if (seen.has(value)) return '[Circular]';
  if (depth >= opts.maxDepth) return '[MaxDepth]';
  seen.add(value);

  if (Array.isArray(value)) {
    const out = value
      .slice(0, opts.maxArrayLength)
      .map((v) => sanitize(v, opts, depth + 1, seen));
    if (value.length > opts.maxArrayLength) {
      out.push(`[+${value.length - opts.maxArrayLength} items]`);
    }
    return out;
  }

  const out = {};
  for (const [key, val] of Object.entries(value)) {
    if (SECRET_KEY_RE.test(key)) {
      out[key] = REDACTED;
    } else if (PII_KEY_RE.test(key) && (typeof val === 'string' || typeof val === 'number')) {
      out[key] = maskPartial(val);
    } else {
      out[key] = sanitize(val, opts, depth + 1, seen);
    }
  }
  return out;
}

function sanitizeHeaders(headers) {
  const out = {};
  for (const [name, val] of Object.entries(headers || {})) {
    out[name] = SENSITIVE_HEADERS.has(name.toLowerCase()) || SECRET_KEY_RE.test(name)
      ? REDACTED
      : val;
  }
  return out;
}

/** Query string vira objeto sanitizado (tokens em ?token=... são removidos). */
function sanitizeQuery(url, opts) {
  try {
    const params = new URL(url, 'http://localhost').searchParams;
    const obj = {};
    for (const [k, v] of params) {
      obj[k] = k in obj ? [].concat(obj[k], v) : v;
    }
    return sanitize(obj, opts);
  } catch {
    return undefined;
  }
}

function isLoggableContentType(contentType = '') {
  const ct = contentType.toLowerCase();
  return LOGGABLE_CONTENT_TYPES.some((t) => ct.startsWith(t)) || ct.includes('+json');
}

function buildBody(req, opts) {
  const contentType = req.headers['content-type'] || '';
  const body = req.body;

  if (body === undefined || body === null) return undefined;

  // Uploads (multipart), binários etc.: só metadados, nunca o conteúdo.
  if (!isLoggableContentType(contentType)) {
    return { omitted: 'content-type não registrado', contentType };
  }
  if (Buffer.isBuffer(body)) {
    return { omitted: 'corpo binário', bytes: body.length };
  }
  if (typeof body === 'object' && Object.keys(body).length === 0) return undefined;

  let size;
  try {
    size = Buffer.byteLength(typeof body === 'string' ? body : JSON.stringify(body));
  } catch {
    return { omitted: 'corpo não serializável' };
  }
  if (size > opts.maxBodyBytes) {
    return { omitted: 'corpo excede o limite', bytes: size, limit: opts.maxBodyBytes };
  }

  return sanitize(body, opts);
}

function createRequestLogger(userOptions = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...userOptions };

  return function requestLogger(req, res, next) {
    if (opts.ignorePaths.includes(req.path)) return next();

    const startedAt = process.hrtime.bigint();
    const startedAtISO = new Date().toISOString();

    // Reaproveita o ID do gateway/balanceador se existir; senão gera um.
    // Devolvê-lo no header permite ao cliente informá-lo ao suporte.
    const requestId = req.headers['x-request-id'] || randomUUID();
    req.id = requestId;
    res.setHeader('X-Request-Id', requestId);

    let logged = false;

    const writeLog = () => {
      if (logged) return;
      logged = true;

      try {
        const { tenantId, userId } = opts.getContext(req) || {};
        const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;

        const entry = {
          event: 'http_request',
          requestId,
          timestamp: startedAtISO,
          tenantId, // essencial para filtrar logs por empresa cliente
          userId,
          method: req.method,
          path: req.originalUrl.split('?')[0],
          route: req.route?.path, // padrão da rota (/clientes/:id), se resolvida
          query: sanitizeQuery(req.originalUrl, opts),
          params: req.params && Object.keys(req.params).length
            ? sanitize(req.params, opts)
            : undefined,
          headers: sanitizeHeaders(req.headers),
          body: buildBody(req, opts),
          ip: req.ip,
          userAgent: req.headers['user-agent'],
          statusCode: res.statusCode,
          responseBytes: Number(res.getHeader('content-length')) || undefined,
          durationMs: Math.round(durationMs * 100) / 100,
          aborted: !res.writableFinished, // cliente fechou antes da resposta
        };

        const level = res.statusCode >= 500 ? 'error' : 'info';
        opts.logger[level](entry);
      } catch (err) {
        // O log jamais pode afetar o fluxo da aplicação.
        try {
          opts.logger.error({ event: 'request_logger_failure', requestId, err: err.message });
        } catch {
          /* silencioso */
        }
      }
    };

    res.on('finish', writeLog);
    res.on('close', writeLog); // cobre conexões abortadas

    next();
  };
}

module.exports = { createRequestLogger, sanitize };

/* ------------------------------------------------------------------ *
 * Exemplo de uso
 * ------------------------------------------------------------------ *
 *
 * const express = require('express');
 * const pino = require('pino');
 * const { createRequestLogger } = require('./requestLogger');
 *
 * const app = express();
 * const logger = pino({ level: 'info' });
 *
 * // Monte ANTES do body parser e da autenticação: o contexto (tenant, usuário
 * // e corpo) é lido só quando a resposta termina.
 * app.use(createRequestLogger({ logger }));
 *
 * app.use(express.json({ limit: '1mb' }));
 * app.use(authMiddleware); // deve preencher req.auth = { tenantId, userId }
 * app.use('/api', routes);
 */