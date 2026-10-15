'use strict';

/**
 * auth-failure-logger.js
 *
 * Middleware (Express/Connect-compatible) que registra tentativas de
 * autenticação malsucedidas para consulta posterior pela equipe de suporte.
 *
 * Requisitos de uso:
 *  - Montar DEPOIS do body parser (express.json / urlencoded).
 *  - Montar apenas nas rotas de autenticação (login, refresh, SSO, MFA...).
 *  - Se houver proxy/load balancer, configurar app.set('trust proxy', ...)
 *    corretamente para que req.ip seja confiável.
 *
 * ---------------------------------------------------------------------
 * DDL sugerido (PostgreSQL) – tabela compartilhada entre tenants:
 *
 * CREATE TABLE auth_failure_logs (
 *   id            BIGSERIAL PRIMARY KEY,
 *   occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
 *   request_id    TEXT,
 *   tenant_id     TEXT,            -- pode ser NULL: a falha pode ocorrer
 *                                  -- antes de o tenant ser identificado
 *   identifier    TEXT,            -- login/e-mail informado (se houver)
 *   status_code   INT NOT NULL,
 *   method        TEXT NOT NULL,
 *   path          TEXT NOT NULL,
 *   ip            INET,
 *   user_agent    TEXT,
 *   reason        TEXT,            -- código interno do motivo da falha
 *   request_data  JSONB NOT NULL   -- headers/query/body já sanitizados
 * );
 * CREATE INDEX ON auth_failure_logs (tenant_id, occurred_at DESC);
 * CREATE INDEX ON auth_failure_logs (tenant_id, identifier, occurred_at DESC);
 * CREATE INDEX ON auth_failure_logs (ip, occurred_at DESC);
 * ---------------------------------------------------------------------
 */

const crypto = require('node:crypto');

/* ------------------------------------------------------------------ */
/* Configuração                                                        */
/* ------------------------------------------------------------------ */

const REDACTED = '[REDACTED]';

// Qualquer chave que combine com este padrão tem o valor mascarado.
const SENSITIVE_KEY =
  /pass|senha|secret|token|authorization|cookie|api[-_]?key|otp|mfa|credential|assertion|signature|private|cvv|card/i;

// Campos de login/identificação que o suporte precisa ver em claro.
const IDENTIFIER_FIELDS = ['email', 'username', 'user', 'login', 'cpf', 'cnpj'];

// Allowlist de headers: só o que é útil para diagnóstico e não é segredo.
const HEADER_ALLOWLIST = new Set([
  'host',
  'user-agent',
  'content-type',
  'content-length',
  'accept',
  'accept-language',
  'origin',
  'referer',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-request-id',
  'x-tenant-id',
]);

const LIMITS = {
  maxDepth: 5,
  maxKeys: 50,
  maxArrayItems: 20,
  maxStringLength: 512,
  maxSerializedBytes: 16 * 1024,
};

const DEFAULT_FAILURE_STATUSES = new Set([401, 403]);

/* ------------------------------------------------------------------ */
/* Sanitização                                                         */
/* ------------------------------------------------------------------ */

function truncate(str) {
  return str.length > LIMITS.maxStringLength
    ? `${str.slice(0, LIMITS.maxStringLength)}…[truncated ${str.length - LIMITS.maxStringLength}]`
    : str;
}

/**
 * Copia o valor recebido mascarando chaves sensíveis e limitando
 * profundidade/tamanho. Nunca altera o objeto original.
 */
function sanitize(value, depth = 0) {
  if (value === null || value === undefined) return value;

  switch (typeof value) {
    case 'string':
      return truncate(value);
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
  if (depth >= LIMITS.maxDepth) return '[MaxDepth]';

  if (Array.isArray(value)) {
    const items = value.slice(0, LIMITS.maxArrayItems).map((v) => sanitize(v, depth + 1));
    if (value.length > LIMITS.maxArrayItems) {
      items.push(`[+${value.length - LIMITS.maxArrayItems} items]`);
    }
    return items;
  }

  const out = {};
  const keys = Object.keys(value);
  for (const key of keys.slice(0, LIMITS.maxKeys)) {
    out[key] = SENSITIVE_KEY.test(key) ? REDACTED : sanitize(value[key], depth + 1);
  }
  if (keys.length > LIMITS.maxKeys) {
    out.__truncatedKeys = keys.length - LIMITS.maxKeys;
  }
  return out;
}

function sanitizeHeaders(headers = {}) {
  const out = {};
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (HEADER_ALLOWLIST.has(lower)) {
      out[lower] = Array.isArray(value) ? value.map(truncate) : truncate(String(value));
    }
  }
  // Não guardamos o valor, apenas o esquema usado (Basic, Bearer...).
  const auth = headers.authorization;
  if (auth) {
    out.authorization = `${String(auth).split(' ')[0]} ${REDACTED}`;
  }
  if (headers.cookie) out.cookie = REDACTED;
  return out;
}

function extractIdentifier(body) {
  if (!body || typeof body !== 'object') return null;
  for (const field of IDENTIFIER_FIELDS) {
    const v = body[field];
    if (typeof v === 'string' && v.trim()) return truncate(v.trim().toLowerCase());
  }
  return null;
}

function resolveTenantId(req) {
  return (
    req.tenant?.id ??
    req.tenantId ??
    (typeof req.headers['x-tenant-id'] === 'string' ? req.headers['x-tenant-id'] : null) ??
    null
  );
}

function safeSerialize(obj) {
  let json = JSON.stringify(obj);
  if (Buffer.byteLength(json) > LIMITS.maxSerializedBytes) {
    json = JSON.stringify({
      truncated: true,
      originalBytes: Buffer.byteLength(json),
      headers: obj.headers,
      note: 'Payload excedeu o limite e foi descartado',
    });
  }
  return json;
}

/* ------------------------------------------------------------------ */
/* Middleware                                                          */
/* ------------------------------------------------------------------ */

/**
 * @param {object}   options
 * @param {{ save(entry: object): Promise<void> }} options.repository
 *        Destino do log (ver createPgRepository abaixo).
 * @param {Set<number>} [options.failureStatuses] Status considerados falha.
 * @param {(err: Error, entry?: object) => void} [options.onError]
 *        Chamado se a gravação falhar (nunca interrompe a requisição).
 */
function authFailureLogger({
  repository,
  failureStatuses = DEFAULT_FAILURE_STATUSES,
  onError = (err) => console.error('[auth-failure-logger] falha ao gravar log:', err.message),
} = {}) {
  if (!repository || typeof repository.save !== 'function') {
    throw new TypeError('authFailureLogger: "repository.save" é obrigatório');
  }

  return function authFailureLoggerMiddleware(req, res, next) {
    // Snapshot sanitizado feito AGORA, antes de qualquer handler mutar req.body.
    const snapshot = {
      requestId: req.headers['x-request-id'] || crypto.randomUUID(),
      startedAt: new Date(),
      headers: sanitizeHeaders(req.headers),
      query: sanitize(req.query),
      body: sanitize(req.body),
      identifier: extractIdentifier(req.body),
    };

    res.on('finish', () => {
      if (!failureStatuses.has(res.statusCode)) return;

      const entry = {
        occurredAt: snapshot.startedAt,
        requestId: snapshot.requestId,
        tenantId: resolveTenantId(req), // lido no fim: o tenant pode ter sido resolvido no handler
        identifier: snapshot.identifier,
        statusCode: res.statusCode,
        method: req.method,
        path: (req.originalUrl || req.url || '').split('?')[0],
        ip: req.ip || req.socket?.remoteAddress || null,
        userAgent: snapshot.headers['user-agent'] || null,
        reason: res.locals?.authFailureReason || null, // handler pode informar: 'INVALID_PASSWORD', 'USER_LOCKED'...
        requestData: JSON.parse(
          safeSerialize({
            headers: snapshot.headers,
            query: snapshot.query,
            body: snapshot.body,
          }),
        ),
      };

      // Fire-and-forget: log nunca pode atrasar nem derrubar a resposta.
      Promise.resolve()
        .then(() => repository.save(entry))
        .catch((err) => onError(err, entry));
    });

    next();
  };
}

/* ------------------------------------------------------------------ */
/* Repositório PostgreSQL (node-postgres)                              */
/* ------------------------------------------------------------------ */

function createPgRepository(pool) {
  return {
    async save(e) {
      await pool.query(
        `INSERT INTO auth_failure_logs
           (occurred_at, request_id, tenant_id, identifier, status_code,
            method, path, ip, user_agent, reason, request_data)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          e.occurredAt,
          e.requestId,
          e.tenantId,
          e.identifier,
          e.statusCode,
          e.method,
          e.path,
          e.ip,
          e.userAgent,
          e.reason,
          JSON.stringify(e.requestData),
        ],
      );
    },

    /**
     * Consulta para o suporte. O tenantId é OBRIGATÓRIO para evitar
     * vazamento de dados entre empresas na base compartilhada.
     */
    async findByTenant(tenantId, { identifier, from, to, limit = 100 } = {}) {
      if (!tenantId) throw new Error('tenantId é obrigatório');
      const { rows } = await pool.query(
        `SELECT * FROM auth_failure_logs
          WHERE tenant_id = $1
            AND ($2::text IS NULL OR identifier = $2)
            AND ($3::timestamptz IS NULL OR occurred_at >= $3)
            AND ($4::timestamptz IS NULL OR occurred_at <= $4)
          ORDER BY occurred_at DESC
          LIMIT $5`,
        [tenantId, identifier ?? null, from ?? null, to ?? null, Math.min(limit, 500)],
      );
      return rows;
    },
  };
}

module.exports = {
  authFailureLogger,
  createPgRepository,
  // exportados para testes unitários
  sanitize,
  sanitizeHeaders,
};

/* ------------------------------------------------------------------ */
/* Exemplo de uso                                                      */
/* ------------------------------------------------------------------ */
/*
const express = require('express');
const { Pool } = require('pg');
const { authFailureLogger, createPgRepository } = require('./auth-failure-logger');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));

const repo = createPgRepository(new Pool({ connectionString: process.env.DATABASE_URL }));

app.post('/auth/login', authFailureLogger({ repository: repo }), async (req, res) => {
  const user = await authService.verify(req.body.email, req.body.password);
  if (!user) {
    res.locals.authFailureReason = 'INVALID_CREDENTIALS';
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }
  res.json({ token: issueToken(user) });
});
*/