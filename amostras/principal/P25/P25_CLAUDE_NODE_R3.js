// middlewares/authFailureLogger.js
'use strict';

const { randomUUID } = require('node:crypto');

// Chaves (comparação case-insensitive, por substring) cujo valor nunca é gravado.
const SENSITIVE_KEY_PATTERNS = [
  'password', 'passwd', 'senha', 'pwd',
  'token', 'secret', 'apikey', 'api_key', 'api-key',
  'authorization', 'cookie', 'set-cookie',
  'otp', 'code', 'codigo', 'pin', 'cvv',
  'cpf', 'cnpj', 'card', 'cartao', 'private',
  'x-csrf', 'x-xsrf',
];

const MAX_DEPTH = 5;
const MAX_STRING = 500;       // trunca valores longos
const MAX_KEYS = 50;          // limita objetos enormes
const REDACTED = '[REDACTED]';

const isSensitiveKey = (key) => {
  const k = String(key).toLowerCase();
  return SENSITIVE_KEY_PATTERNS.some((p) => k.includes(p));
};

function sanitize(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (depth > MAX_DEPTH) return '[TRUNCATED_DEPTH]';

  if (typeof value === 'string') {
    // remove caracteres de controle (evita log injection / quebra de linha)
    const clean = value.replace(/[\u0000-\u001f\u007f]/g, ' ');
    return clean.length > MAX_STRING ? clean.slice(0, MAX_STRING) + '…[TRUNCATED]' : clean;
  }
  if (typeof value !== 'object') return value;

  if (Array.isArray(value)) {
    return value.slice(0, MAX_KEYS).map((v) => sanitize(v, depth + 1));
  }

  const out = {};
  for (const key of Object.keys(value).slice(0, MAX_KEYS)) {
    out[key] = isSensitiveKey(key) ? REDACTED : sanitize(value[key], depth + 1);
  }
  return out;
}

function sanitizeHeaders(headers) {
  const out = {};
  for (const [name, val] of Object.entries(headers || {})) {
    if (name.toLowerCase() === 'authorization') {
      // mantém só o esquema (Basic/Bearer) para diagnóstico
      out[name] = `${String(val).split(' ')[0]} ${REDACTED}`;
    } else if (isSensitiveKey(name)) {
      out[name] = REDACTED;
    } else {
      out[name] = sanitize(val);
    }
  }
  return out;
}

/**
 * @param {object} opts
 * @param {{ query: Function }} opts.db  - pool do pg (ou compatível)
 * @param {(req) => string|null} [opts.getTenantId]
 * @param {number[]} [opts.statuses]     - status HTTP considerados falha de autenticação
 * @param {(req) => boolean} [opts.isAuthRoute] - restringe às rotas de autenticação
 * @param {{ error: Function }} [opts.logger]
 */
function authFailureLogger({
  db,
  getTenantId = (req) => req.tenant?.id ?? null,
  statuses = [401, 403],
  isAuthRoute = (req) => /^\/(api\/)?(v\d+\/)?auth\//.test(req.path),
  logger = console,
} = {}) {
  if (!db) throw new Error('authFailureLogger: "db" é obrigatório');

  return function authFailureLoggerMiddleware(req, res, next) {
    req.id = req.id || req.get('x-request-id') || randomUUID();

    res.on('finish', () => {
      if (!isAuthRoute(req) || !statuses.includes(res.statusCode)) return;

      const body = req.body && typeof req.body === 'object' ? req.body : {};
      const identifier =
        body.email || body.username || body.login || body.user || null;

      const requestData = {
        query: sanitize(req.query),
        headers: sanitizeHeaders(req.headers),
        body: sanitize(body),
      };

      // Fire-and-forget: o log nunca pode atrasar ou derrubar a resposta.
      db.query(
        `INSERT INTO auth_failure_logs
           (request_id, tenant_id, identifier, ip, user_agent,
            method, path, status_code, reason, request_data)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          req.id,
          getTenantId(req),
          identifier ? String(identifier).slice(0, 255) : null,
          req.ip,
          (req.get('user-agent') || '').slice(0, 500),
          req.method,
          req.path,
          res.statusCode,
          res.locals.authFailureReason || null,
          JSON.stringify(requestData),
        ]
      ).catch((err) => {
        logger.error('[authFailureLogger] falha ao gravar log:', err.message);
      });
    });

    next();
  };
}

module.exports = { authFailureLogger, sanitize };