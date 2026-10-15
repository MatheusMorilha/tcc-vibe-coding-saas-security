'use strict';

const { randomUUID } = require('node:crypto');

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------
const DEFAULTS = {
  maxBodyChars: 8 * 1024,      // limite do body serializado no log
  maxStringChars: 512,         // limite por string individual
  maxArrayItems: 50,
  maxDepth: 6,
  ignorePaths: ['/health', '/healthz', '/ready', '/metrics'],
  // Chaves cujo valor nunca deve ser gravado (comparação case-insensitive,
  // ignorando "_" e "-")
  sensitiveKeys: [
    'password', 'senha', 'newpassword', 'oldpassword', 'confirmpassword',
    'token', 'accesstoken', 'refreshtoken', 'idtoken', 'secret', 'clientsecret',
    'apikey', 'authorization', 'cookie', 'setcookie', 'privatekey',
    'cardnumber', 'numerocartao', 'cvv', 'cvc', 'pin',
    'cpf', 'cnpj', 'rg', 'ssn', 'taxid',
  ],
  // Headers gravados em allowlist; os demais são descartados
  allowedHeaders: [
    'content-type', 'content-length', 'accept', 'accept-language',
    'user-agent', 'origin', 'referer', 'x-request-id', 'x-forwarded-for',
    'x-api-version', 'x-client-version',
  ],
  // Resolve o contexto de tenant/usuário a partir do req (após autenticação)
  getContext: (req) => ({
    tenantId: req.auth?.tenantId ?? req.tenant?.id ?? null,
    userId: req.auth?.userId ?? req.user?.id ?? null,
  }),
  // Destino do log. Deve ser uma função que aceita um objeto.
  sink: (entry) => process.stdout.write(JSON.stringify(entry) + '\n'),
};

const REDACTED = '[REDACTED]';
const normalizeKey = (k) => String(k).toLowerCase().replace(/[_\-\s]/g, '');

// Padrões de valores sensíveis mesmo em campos "inocentes"
const VALUE_PATTERNS = [
  [/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi, 'Bearer [REDACTED]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '[REDACTED_JWT]'],
  [/\b(?:\d[ -]?){13,19}\b/g, '[REDACTED_CARD]'],
];

// ---------------------------------------------------------------------------
// Sanitização
// ---------------------------------------------------------------------------
function createSanitizer(opts) {
  const sensitive = new Set(opts.sensitiveKeys.map(normalizeKey));

  function sanitizeString(str) {
    let out = str;
    for (const [re, repl] of VALUE_PATTERNS) out = out.replace(re, repl);
    if (out.length > opts.maxStringChars) {
      out = out.slice(0, opts.maxStringChars) + `…[truncated ${str.length - opts.maxStringChars} chars]`;
    }
    return out;
  }

  function sanitize(value, depth = 0, seen = new WeakSet()) {
    if (value === null || value === undefined) return value;
    if (typeof value === 'string') return sanitizeString(value);
    if (typeof value === 'number' || typeof value === 'boolean') return value;
    if (typeof value === 'bigint') return value.toString();
    if (Buffer.isBuffer(value)) return `[Buffer ${value.length} bytes]`;
    if (typeof value !== 'object') return `[${typeof value}]`;

    if (seen.has(value)) return '[Circular]';
    if (depth >= opts.maxDepth) return '[MaxDepth]';
    seen.add(value);

    if (Array.isArray(value)) {
      const items = value.slice(0, opts.maxArrayItems).map((v) => sanitize(v, depth + 1, seen));
      if (value.length > opts.maxArrayItems) {
        items.push(`…[${value.length - opts.maxArrayItems} more items]`);
      }
      return items;
    }

    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = sensitive.has(normalizeKey(k)) ? REDACTED : sanitize(v, depth + 1, seen);
    }
    return out;
  }

  function sanitizeQuery(url) {
    const [path, qs] = url.split('?');
    if (!qs) return { path, query: undefined };
    const params = new URLSearchParams(qs);
    const query = {};
    for (const [k, v] of params) {
      query[k] = sensitive.has(normalizeKey(k)) ? REDACTED : sanitizeString(v);
    }
    return { path, query };
  }

  function sanitizeHeaders(headers) {
    const out = {};
    for (const name of opts.allowedHeaders) {
      if (headers[name] !== undefined) out[name] = sanitizeString(String(headers[name]));
    }
    // Registra apenas a PRESENÇA de credenciais, nunca o valor
    out['authorization'] = headers['authorization'] ? REDACTED : undefined;
    out['cookie'] = headers['cookie'] ? REDACTED : undefined;
    return out;
  }

  return { sanitize, sanitizeQuery, sanitizeHeaders };
}

// ---------------------------------------------------------------------------
// Captura do body
// ---------------------------------------------------------------------------
function describeBody(req, sanitize, maxBodyChars) {
  const contentType = String(req.headers['content-type'] || '');

  // Uploads e binários: não gravar conteúdo
  if (/multipart\/|octet-stream|image\/|video\/|audio\/|application\/pdf/i.test(contentType)) {
    return { omitted: true, reason: 'binary_or_multipart', contentType };
  }

  if (req.body === undefined || req.body === null) return undefined;
  if (typeof req.body === 'object' && Object.keys(req.body).length === 0) return undefined;

  const clean = sanitize(req.body);
  const serialized = JSON.stringify(clean);
  if (serialized && serialized.length > maxBodyChars) {
    return {
      truncated: true,
      originalSize: serialized.length,
      preview: serialized.slice(0, maxBodyChars),
    };
  }
  return clean;
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
function requestLogger(userOptions = {}) {
  const opts = { ...DEFAULTS, ...userOptions };
  const { sanitize, sanitizeQuery, sanitizeHeaders } = createSanitizer(opts);
  const ignore = new Set(opts.ignorePaths);

  return function requestLoggerMiddleware(req, res, next) {
    const path = (req.originalUrl || req.url).split('?')[0];
    if (ignore.has(path)) return next();

    const startedAt = process.hrtime.bigint();
    const startedAtIso = new Date().toISOString();

    // ID de correlação: aceita o do cliente apenas se for seguro
    const incoming = req.headers['x-request-id'];
    const requestId =
      typeof incoming === 'string' && /^[A-Za-z0-9\-_.]{8,64}$/.test(incoming)
        ? incoming
        : randomUUID();
    req.id = requestId;
    res.setHeader('X-Request-Id', requestId);

    let logged = false;
    const writeLog = (aborted) => {
      if (logged) return;
      logged = true;

      try {
        const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
        const { path: cleanPath, query } = sanitizeQuery(req.originalUrl || req.url);

        // Contexto lido no final, quando a autenticação já populou o req
        const { tenantId, userId } = opts.getContext(req);

        const entry = {
          timestamp: startedAtIso,
          level: res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info',
          type: 'http_request',
          requestId,
          tenantId,
          userId,
          method: req.method,
          path: cleanPath,
          route: req.route?.path, // padrão da rota (ex.: /clientes/:id), se disponível
          query,
          headers: sanitizeHeaders(req.headers),
          body: describeBody(req, sanitize, opts.maxBodyChars),
          ip: req.ip || req.socket?.remoteAddress,
          statusCode: res.statusCode,
          responseBytes: Number(res.getHeader('content-length')) || undefined,
          durationMs: Math.round(durationMs * 100) / 100,
          aborted,
        };

        opts.sink(entry);
      } catch (err) {
        // Falha de log nunca pode derrubar ou alterar a resposta
        process.stderr.write(`[request-logger] falha ao gravar log: ${err.message}\n`);
      }
    };

    res.on('finish', () => writeLog(false));
    res.on('close', () => writeLog(!res.writableFinished)); // cliente desconectou

    next();
  };
}

module.exports = { requestLogger };