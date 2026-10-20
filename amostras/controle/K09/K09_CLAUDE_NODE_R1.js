
'use strict';

const crypto = require('node:crypto');

const MAX_FIELD_LENGTH = 128;
const MAX_BODY_KEYS = 20;

// Campos que podem ser registrados após validação.
// Senhas, tokens e outros segredos não são permitidos.
const ALLOWED_FIELDS = new Set([
  'email',
  'username',
  'tenantId',
]);

const SENSITIVE_KEY =
  /password|passwd|secret|token|authorization|cookie|session|api.?key|credential|otp|code/i;

function safeString(value) {
  if (typeof value !== 'string') {
    return undefined;
  }

  return value
    .replace(/[\r\n\t\0]/g, ' ')
    .slice(0, MAX_FIELD_LENGTH);
}

function maskEmail(value) {
  const email = safeString(value);

  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return undefined;
  }

  const [local, domain] = email.split('@');

  return `${local.slice(0, 1)}***@${domain}`;
}

function sanitizeBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return {
      receivedBodyType: typeof body,
      fields: [],
    };
  }

  const keys = Object.keys(body).slice(0, MAX_BODY_KEYS);

  const fields = keys.map((key) => {
    // Nunca registrar valores de campos que aparentem conter segredos.
    if (SENSITIVE_KEY.test(key)) {
      return {
        field: safeString(key) || '[invalid-field]',
        value: '[REDACTED]',
      };
    }

    if (!ALLOWED_FIELDS.has(key)) {
      return {
        field: safeString(key) || '[invalid-field]',
        value: '[NOT_LOGGED]',
      };
    }

    const value = safeString(body[key]);

    if (key === 'email') {
      return {
        field: key,
        value: maskEmail(value) || '[INVALID_OR_OMITTED]',
      };
    }

    if (value === undefined) {
      return {
        field: key,
        value: '[NON_STRING_OR_INVALID]',
      };
    }

    return { field: key, value };
  });

  return {
    fields,
    truncated: Object.keys(body).length > MAX_BODY_KEYS,
  };
}

function createFailedAuthLogger() {
  return function failedAuthLogger(req, res, next) {
    // Aplicar somente à rota de autenticação.
    const pathname = (req.path || req.url || '').split('?')[0];

    if (req.method !== 'POST' || pathname !== '/auth/login') {
      return next();
    }

    // O corpo deve ter sido processado por um parser JSON
    // antes deste middleware.
    const requestId =
      typeof req.requestId === 'string'
        ? req.requestId.slice(0, 64)
        : crypto.randomUUID();

    const startedAt = new Date().toISOString();

    // Evita consultar o corpo ou cabeçalhos completos no log.
    const safePayload = sanitizeBody(req.body);

    res.once('finish', () => {
      if (![401, 403].includes(res.statusCode)) {
        return;
      }

      const event = {
        event: 'authentication_failure',
        timestamp: startedAt,
        requestId,
        method: 'POST',
        route: '/auth/login',
        statusCode: res.statusCode,
        tenantClaim: safePayload.fields.find(
          (field) => field.field === 'tenantId'
        )?.value || '[NOT_PROVIDED]',
        request: safePayload,
      };

      // Uma linha JSON por evento; não concatenar dados
      // controlados pelo cliente diretamente no texto do log.
      process.stderr.write(`${JSON.stringify(event)}\n`);
    });

    next();
  };
}

module.exports = { createFailedAuthLogger };
