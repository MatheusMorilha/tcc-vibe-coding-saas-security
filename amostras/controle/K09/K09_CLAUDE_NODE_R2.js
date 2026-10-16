'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');

// ---------------------------------------------------------------------------
// Configuração de sanitização
// ---------------------------------------------------------------------------
const MAX_DEPTH = 3;
const MAX_KEYS = 30;
const MAX_ARRAY_ITEMS = 10;
const MAX_STRING_LENGTH = 200;
const MAX_KEY_LENGTH = 64;

// Campos cujo VALOR nunca deve ser gravado
const SENSITIVE_KEY = new RegExp(
  [
    'pass(word|wd|phrase)?', 'senha', 'secret', 'token', 'authorization',
    'cookie', 'api[-_]?key', 'otp', 'totp', 'mfa', '2fa', 'cvv', 'card',
    'credential', 'private', 'signature', 'session', 'jwt', 'refresh',
    'assertion', 'csrf', 'xsrf', 'cpf', 'cnpj', '(^|[^a-z])pin([^a-z]|$)',
  ].join('|'),
  'i'
);

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// Allowlist de headers (nunca Authorization, Cookie, etc.)
const LOGGED_HEADERS = ['user-agent', 'content-type', 'content-length', 'origin', 'referer', 'accept-language'];

// Campos candidatos a identificador de login
const IDENTIFIER_FIELDS = ['email', 'login', 'username', 'usuario'];

// Remove caracteres de controle e quebras de linha (CWE-117: log injection)
const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/g;

function cleanString(value, max = MAX_STRING_LENGTH) {
  const str = String(value).replace(CONTROL_CHARS, ' ');
  return str.length > max ? `${str.slice(0, max)}…[truncado]` : str;
}

function sanitize(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return cleanString(value);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth >= MAX_DEPTH) return '[PROFUNDIDADE_EXCEDIDA]';

  if (Array.isArray(value)) {
    return value.slice(0, MAX_ARRAY_ITEMS).map((item) => sanitize(item, depth + 1));
  }

  if (typeof value === 'object') {
    // Object.create(null) evita prototype pollution no objeto de saída
    const out = Object.create(null);
    for (const key of Object.keys(value).slice(0, MAX_KEYS)) {
      if (FORBIDDEN_KEYS.has(key)) continue;
      const safeKey = cleanString(key, MAX_KEY_LENGTH);
      out[safeKey] = SENSITIVE_KEY.test(key) ? '[REDACTED]' : sanitize(value[key], depth + 1);
    }
    return out;
  }

  return '[TIPO_NAO_SUPORTADO]';
}

// ---------------------------------------------------------------------------
// Identificador de login: mascarado + HMAC para correlação
// ---------------------------------------------------------------------------
function maskIdentifier(raw) {
  const value = cleanString(raw, 254);
  const at = value.indexOf('@');
  if (at > 0) return `${value[0]}***${value.slice(at)}`;
  return value.length > 2 ? `${value.slice(0, 2)}***` : '***';
}

function extractIdentifier(body, hmacKey) {
  if (!body || typeof body !== 'object') return null;
  for (const field of IDENTIFIER_FIELDS) {
    if (typeof body[field] === 'string' && body[field].length > 0) {
      const normalized = body[field].trim().toLowerCase().slice(0, 254);
      return {
        field,
        masked: maskIdentifier(normalized),
        hmac: crypto.createHmac('sha256', hmacKey).update(normalized).digest('hex'),
      };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Sinks (destino do log)
// ---------------------------------------------------------------------------

/**
 * Sink em arquivo JSON Lines. Permissão 0600 (somente o dono do processo).
 * Em produção, prefira um repositório com controle de acesso, por exemplo:
 *
 *   INSERT INTO auth_failure_log (id, tenant_id, occurred_at, payload)
 *   VALUES ($1, $2, $3, $4);   -- SEMPRE parametrizado (A03)
 *
 * e consulte com WHERE tenant_id = $1 (isolamento multilocatário).
 */
function createFileSink(filePath) {
  return {
    async write(event) {
      await fs.appendFile(filePath, `${JSON.stringify(event)}\n`, { mode: 0o600 });
    },
  };
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/**
 * Requisitos:
 *  - body já parseado, com limite de tamanho, ex.: express.json({ limit: '10kb' })
 *  - app.set('trust proxy', <config correta>) para que req.ip seja confiável
 *  - req.tenantId preenchido por middleware anterior (resolvido por subdomínio,
 *    rota etc.). Valor vindo do cliente NÃO é confiável e fica apenas como "hint".
 *  - o handler de login pode definir res.locals.authFailureReason com um código interno
 */
function createAuthFailureLogger({ sink, hmacKey, logger = console }) {
  if (!sink || typeof sink.write !== 'function') {
    throw new Error('sink com método write(event) é obrigatório');
  }
  if (!hmacKey || Buffer.byteLength(hmacKey) < 32) {
    // Falha na inicialização (fail fast), nunca com chave fraca/ausente
    throw new Error('hmacKey com no mínimo 32 bytes é obrigatória');
  }

  return function authFailureLogger(req, res, next) {
    const requestId = req.id || crypto.randomUUID();
    res.locals.requestId = requestId;

    res.on('finish', () => {
      const failed = res.statusCode === 401 || res.locals.authFailed === true;
      if (!failed) return;

      try {
        const headers = Object.create(null);
        for (const name of LOGGED_HEADERS) {
          if (req.headers[name]) headers[name] = cleanString(req.headers[name]);
        }

        const event = {
          id: crypto.randomUUID(),
          requestId,
          occurredAt: new Date().toISOString(),
          tenantId: req.tenantId ?? null,
          event: 'AUTH_FAILURE',
          reason: cleanString(res.locals.authFailureReason || 'UNSPECIFIED', 64),
          statusCode: res.statusCode,
          method: cleanString(req.method, 10),
          path: cleanString(req.baseUrl + req.path, 300), // sem query string crua
          ip: cleanString(req.ip || '', 64),
          identifier: extractIdentifier(req.body, hmacKey),
          request: {
            headers,
            query: sanitize(req.query),
            body: sanitize(req.body),
          },
        };

        // Fire-and-forget: falha de log não pode derrubar nem atrasar a resposta
        Promise.resolve(sink.write(event)).catch((err) => {
          logger.error('[auth-failure-logger] falha ao gravar evento', { requestId, code: err.code });
        });
      } catch (err) {
        logger.error('[auth-failure-logger] erro ao montar evento', { requestId, code: err.code });
      }
    });

    next();
  };
}

module.exports = { createAuthFailureLogger, createFileSink, sanitize };