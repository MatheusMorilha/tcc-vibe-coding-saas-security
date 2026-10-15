'use strict';

/**
 * Middleware de log de requisições para API SaaS multilocatária.
 *
 * Objetivo: permitir que o suporte reconstitua o que foi enviado em cada chamada,
 * sem gravar segredos nem dados pessoais sensíveis (LGPD).
 *
 * Decisões principais:
 *  - Cada registro carrega tenantId/userId (resolvidos no FINAL da requisição,
 *    depois da autenticação), para que o suporte filtre sempre por empresa.
 *  - O tenantId vem do contexto autenticado (req.auth), NUNCA de header/body
 *    enviado pelo cliente.
 *  - Corpo, query e headers passam por redação de campos sensíveis ANTES de
 *    qualquer gravação. O corpo é copiado (snapshot) na entrada, então reflete
 *    o que o cliente enviou, mesmo que um handler o altere depois.
 *  - Uma entrada por requisição, com status e duração.
 *  - Falha de log jamais derruba nem atrasa a requisição.
 *
 * Ordem de montagem (Express):
 *   app.use(express.json({ limit: '1mb' }));   // 1) parser de corpo
 *   app.use(requestLogger({ sink }));          // 2) logger (antes da autenticação,
 *   app.use(authenticate);                     //    para registrar também os 401/403)
 */

const { randomUUID } = require('node:crypto');
const { performance } = require('node:perf_hooks');

const REDACTED = '[REDACTED]';

// Comparação feita sobre a chave normalizada (minúscula, sem símbolos):
// "api_key", "Api-Key" e "apiKey" viram "apikey".
const DEFAULT_SENSITIVE_KEYS = [
  'password', 'passwd', 'senha', 'secret', 'token', 'authorization',
  'cookie', 'apikey', 'privatekey', 'credential', 'signature',
  'cardnumber', 'numerocartao', 'cartao', 'cvv', 'cvc', 'securitycode',
];

// Mascaramento parcial: mantém só os 2 últimos caracteres (útil ao suporte
// para conferir identidade sem expor o dado completo).
const DEFAULT_PARTIAL_MASK_KEYS = ['cpf', 'cnpj'];

const DEFAULT_SAFE_BODY_TYPES = [
  'application/json',
  'application/x-www-form-urlencoded',
  'text/plain',
  'application/xml',
  'text/xml',
];

const normalizeKey = (key) => String(key).toLowerCase().replace(/[^a-z0-9]/g, '');

function createRedactor(options) {
  const sensitive = options.sensitiveKeys.map(normalizeKey);
  const partial = new Set(options.partialMaskKeys.map(normalizeKey));

  const isSensitive = (key) => {
    const k = normalizeKey(key);
    return sensitive.some((s) => k.includes(s));
  };

  const maskPartially = (value) => {
    const str = String(value);
    return str.length <= 2 ? '**' : `${'*'.repeat(str.length - 2)}${str.slice(-2)}`;
  };

  function redact(value, depth = 0, seen = new WeakSet()) {
    if (value === null || value === undefined) return value;

    switch (typeof value) {
      case 'string':
        return value.length > options.maxStringLength
          ? `${value.slice(0, options.maxStringLength)}…[truncated ${value.length - options.maxStringLength} chars]`
          : value;
      case 'number':
      case 'boolean':
        return value;
      case 'bigint':
        return value.toString();
      case 'object':
        break;
      default:
        return `[${typeof value}]`; // function, symbol...
    }

    if (Buffer.isBuffer(value)) return `[Buffer ${value.length} bytes]`;
    if (seen.has(value)) return '[Circular]';
    if (depth >= options.maxDepth) return '[MaxDepth]';
    seen.add(value);

    if (Array.isArray(value)) {
      const items = value.slice(0, options.maxArrayItems).map((v) => redact(v, depth + 1, seen));
      if (value.length > options.maxArrayItems) {
        items.push(`[+${value.length - options.maxArrayItems} items omitted]`);
      }
      return items;
    }

    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (isSensitive(k)) out[k] = REDACTED;
      else if (partial.has(normalizeKey(k)) && v != null && typeof v !== 'object') out[k] = maskPartially(v);
      else out[k] = redact(v, depth + 1, seen);
    }
    return out;
  }

  return redact;
}

function defaultSink(entry) {
  process.stdout.write(`${JSON.stringify(entry)}\n`);
}

function defaultOnError(err) {
  process.stderr.write(`[requestLogger] falha ao gravar log: ${err && err.message}\n`);
}

function requestLogger(userOptions = {}) {
  const options = {
    sink: defaultSink,                     // (entry) => void | Promise<void>
    onError: defaultOnError,
    skipPaths: ['/health', '/healthz', '/ready'],
    sensitiveKeys: DEFAULT_SENSITIVE_KEYS,
    partialMaskKeys: DEFAULT_PARTIAL_MASK_KEYS,
    safeBodyTypes: DEFAULT_SAFE_BODY_TYPES,
    maxBodyBytes: 16 * 1024,               // tamanho máximo do corpo serializado no log
    maxStringLength: 1000,
    maxArrayItems: 100,
    maxDepth: 8,
    // Resolvidos ao final da requisição, a partir do contexto autenticado.
    getTenantId: (req) => (req.auth && req.auth.tenantId) || (req.tenant && req.tenant.id) || null,
    getUserId: (req) => (req.auth && req.auth.userId) || (req.user && req.user.id) || null,
    ...userOptions,
  };

  const redact = createRedactor(options);
  const skip = new Set(options.skipPaths);

  function snapshotBody(req) {
    const contentType = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    const contentLength = Number(req.headers['content-length'] || 0);

    if (!contentLength && (req.body === undefined || req.body === null)) {
      return { body: null, bodyOmitted: null, bodyTruncated: false };
    }
    if (contentType && !options.safeBodyTypes.includes(contentType)) {
      // multipart/uploads/binários: registra só os metadados
      return { body: null, bodyOmitted: `content-type não registrado: ${contentType}`, bodyTruncated: false };
    }
    if (req.body === undefined) {
      return { body: null, bodyOmitted: 'corpo não interpretado (parser ausente ou antes do logger)', bodyTruncated: false };
    }

    const redacted = redact(req.body);
    const serialized = JSON.stringify(redacted);
    if (serialized && Buffer.byteLength(serialized) > options.maxBodyBytes) {
      return {
        body: `${serialized.slice(0, options.maxBodyBytes)}…`,
        bodyOmitted: null,
        bodyTruncated: true,
      };
    }
    return { body: redacted, bodyOmitted: null, bodyTruncated: false };
  }

  function emit(entry) {
    try {
      const result = options.sink(entry);
      if (result && typeof result.catch === 'function') result.catch(options.onError);
    } catch (err) {
      options.onError(err);
    }
  }

  return function requestLoggerMiddleware(req, res, next) {
    // Path sem query string: tokens em URL não podem vazar pelo log.
    const path = (req.originalUrl || req.url || '').split('?')[0];
    if (skip.has(path)) return next();

    const startedAt = performance.now();
    const receivedAt = new Date().toISOString();

    const incomingId = req.headers['x-request-id'];
    const requestId =
      typeof incomingId === 'string' && /^[\w.-]{8,128}$/.test(incomingId) ? incomingId : randomUUID();
    req.id = requestId;
    res.setHeader('X-Request-Id', requestId); // o cliente informa este ID ao suporte

    // Snapshot protegido: nunca pode interromper a requisição.
    let request;
    try {
      request = {
        query: redact(req.query || {}),
        headers: redact(req.headers),
        ...snapshotBody(req),
      };
    } catch (err) {
      options.onError(err);
      request = { query: null, headers: null, body: null, bodyOmitted: 'erro ao capturar', bodyTruncated: false };
    }

    let logged = false;
    const finalize = () => {
      if (logged) return;
      logged = true;
      try {
        emit({
          timestamp: receivedAt,
          requestId,
          tenantId: options.getTenantId(req),
          userId: options.getUserId(req),
          method: req.method,
          path,
          route: req.route ? `${req.baseUrl || ''}${req.route.path}` : null,
          ip: req.ip || (req.socket && req.socket.remoteAddress) || null,
          ...request,
          status: res.statusCode,
          aborted: !res.writableFinished, // cliente fechou a conexão antes da resposta
          durationMs: Math.round((performance.now() - startedAt) * 100) / 100,
        });
      } catch (err) {
        options.onError(err);
      }
    };

    res.on('finish', finalize);
    res.on('close', finalize);

    next();
  };
}

module.exports = { requestLogger, REDACTED };

/* ---------------------------------------------------------------------------
 * Exemplo de uso
 *
 * const express = require('express');
 * const { requestLogger } = require('./requestLogger');
 *
 * const app = express();
 * app.use(express.json({ limit: '1mb' }));
 *
 * app.use(requestLogger({
 *   // Exemplo: enviar para fila/tabela particionada por tenant.
 *   sink: async (entry) => { await auditQueue.publish(entry); },
 * }));
 *
 * app.use(authenticate); // deve preencher req.auth = { tenantId, userId }
 * --------------------------------------------------------------------------- */