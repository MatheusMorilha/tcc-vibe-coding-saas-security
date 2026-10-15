'use strict';

/**
 * failedAuthLogger.js
 *
 * Middleware que registra tentativas de autenticação malsucedidas
 * (HTTP 401/403 por padrão), guardando o conteúdo da requisição para
 * consulta posterior pelo suporte, SEM gravar segredos em texto puro.
 *
 * Uso:
 *   app.use(express.json());
 *   app.use(resolveTenant);                       // popula req.tenant
 *   app.use(failedAuthLogger({ store: pgStore(pool) }));
 *   app.use('/auth', authRoutes);
 *
 * Os handlers de autenticação podem informar o motivo da falha:
 *   res.locals.authFailureReason = 'INVALID_PASSWORD';
 *
 * -----------------------------------------------------------------
 * SCHEMA (PostgreSQL) – base compartilhada entre tenants
 * -----------------------------------------------------------------
 * CREATE TABLE failed_auth_logs (
 *   id            BIGSERIAL PRIMARY KEY,
 *   tenant_id     UUID NULL,              -- NULL quando o tenant não foi identificado
 *   request_id    TEXT,
 *   occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
 *   ip            INET,
 *   user_agent    TEXT,
 *   method        TEXT NOT NULL,
 *   path          TEXT NOT NULL,
 *   status_code   INT  NOT NULL,
 *   identifier    TEXT,                   -- login/e-mail informado (não é segredo)
 *   reason        TEXT,
 *   request_data  JSONB NOT NULL          -- query, headers e body já mascarados
 * );
 * CREATE INDEX ON failed_auth_logs (tenant_id, occurred_at DESC);
 * CREATE INDEX ON failed_auth_logs (tenant_id, identifier);
 *
 * -- Recomendado: isolamento por tenant também no banco (RLS)
 * -- ALTER TABLE failed_auth_logs ENABLE ROW LEVEL SECURITY;
 * -- CREATE POLICY tenant_isolation ON failed_auth_logs
 * --   USING (tenant_id = current_setting('app.tenant_id')::uuid);
 */

const REDACTED = '[REDACTED]';

// Chaves (case-insensitive, comparadas por "contém") cujo valor jamais é gravado.
const DEFAULT_SENSITIVE_KEYS = [
  'password', 'passwd', 'senha', 'pass',
  'token', 'secret', 'apikey', 'api_key', 'api-key',
  'authorization', 'cookie', 'set-cookie',
  'otp', 'totp', 'mfa', 'cvv', 'cardnumber', 'cpf_token',
  'x-csrf', 'x-xsrf', 'signature',
];

// Headers que valem a pena guardar (allowlist); o resto é descartado.
const DEFAULT_HEADER_ALLOWLIST = [
  'host', 'origin', 'referer', 'user-agent', 'content-type',
  'content-length', 'accept', 'accept-language', 'x-forwarded-for',
  'x-request-id', 'x-tenant-id', 'authorization', 'cookie',
];

const MAX_DEPTH = 6;
const MAX_STRING = 500;
const MAX_KEYS = 100;

function isSensitive(key, sensitiveKeys) {
  const k = String(key).toLowerCase();
  return sensitiveKeys.some((s) => k.includes(s));
}

/** Copia profunda com mascaramento, limites de profundidade/tamanho. */
function sanitize(value, sensitiveKeys, depth = 0) {
  if (value === null || value === undefined) return value;
  if (depth > MAX_DEPTH) return '[TRUNCATED_DEPTH]';

  if (typeof value === 'string') {
    return value.length > MAX_STRING
      ? value.slice(0, MAX_STRING) + `…[+${value.length - MAX_STRING} chars]`
      : value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Buffer.isBuffer(value)) return `[BINARY ${value.length} bytes]`;

  if (Array.isArray(value)) {
    return value.slice(0, MAX_KEYS).map((v) => sanitize(v, sensitiveKeys, depth + 1));
  }

  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).slice(0, MAX_KEYS)) {
      out[key] = isSensitive(key, sensitiveKeys)
        ? REDACTED
        : sanitize(value[key], sensitiveKeys, depth + 1);
    }
    return out;
  }

  return String(value).slice(0, MAX_STRING); // função, symbol, bigint etc.
}

function pickHeaders(headers, allowlist, sensitiveKeys) {
  const out = {};
  for (const name of allowlist) {
    if (headers[name] === undefined) continue;
    out[name] = isSensitive(name, sensitiveKeys)
      ? REDACTED
      : sanitize(headers[name], sensitiveKeys);
  }
  return out;
}

function extractIdentifier(body) {
  if (!body || typeof body !== 'object') return null;
  const candidate = body.email ?? body.login ?? body.username ?? body.user ?? null;
  return typeof candidate === 'string' ? candidate.trim().slice(0, 254) : null;
}

function failedAuthLogger({
  store,                                   // { insert(entry): Promise<void> }
  isFailure = (res) => res.statusCode === 401 || res.statusCode === 403,
  sensitiveKeys = DEFAULT_SENSITIVE_KEYS,
  headerAllowlist = DEFAULT_HEADER_ALLOWLIST,
  onError = (err) => console.error('[failedAuthLogger] falha ao gravar log:', err.message),
} = {}) {
  if (!store || typeof store.insert !== 'function') {
    throw new Error('failedAuthLogger: "store.insert" é obrigatório');
  }

  return function failedAuthLoggerMiddleware(req, res, next) {
    // Snapshot sanitizado no início: handlers posteriores podem alterar req.body,
    // e assim o segredo não fica retido em memória além do necessário.
    const snapshot = {
      query: sanitize(req.query, sensitiveKeys),
      headers: pickHeaders(req.headers, headerAllowlist, sensitiveKeys),
      body: sanitize(req.body, sensitiveKeys),
      identifier: extractIdentifier(req.body),
    };

    res.on('finish', () => {
      if (!isFailure(res)) return;

      const entry = {
        tenantId: req.tenant?.id ?? null,   // definido por um middleware anterior
        requestId: req.id ?? req.headers['x-request-id'] ?? null,
        ip: req.ip ?? req.socket?.remoteAddress ?? null,
        userAgent: String(req.headers['user-agent'] ?? '').slice(0, 300),
        method: req.method,
        path: (req.originalUrl || req.url).split('?')[0].slice(0, 300),
        statusCode: res.statusCode,
        identifier: snapshot.identifier,
        reason: res.locals?.authFailureReason ?? null,
        requestData: {
          query: snapshot.query,
          headers: snapshot.headers,
          body: snapshot.body,
        },
      };

      // Fire-and-forget: o log nunca pode atrasar ou derrubar a resposta.
      Promise.resolve()
        .then(() => store.insert(entry))
        .catch(onError);
    });

    next();
  };
}

/* ------------------------------------------------------------------ */
/* Store PostgreSQL + consulta para o suporte (sempre filtrada por    */
/* tenant, para não expor dados de uma empresa a outra)                */
/* ------------------------------------------------------------------ */

function pgStore(pool) {
  return {
    async insert(e) {
      await pool.query(
        `INSERT INTO failed_auth_logs
           (tenant_id, request_id, ip, user_agent, method, path,
            status_code, identifier, reason, request_data)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          e.tenantId, e.requestId, e.ip, e.userAgent, e.method, e.path,
          e.statusCode, e.identifier, e.reason, JSON.stringify(e.requestData),
        ]
      );
    },

    // tenantId é obrigatório por design.
    async findByTenant(tenantId, { identifier, from, to, limit = 50, offset = 0 } = {}) {
      if (!tenantId) throw new Error('tenantId é obrigatório');
      const { rows } = await pool.query(
        `SELECT id, occurred_at, ip, method, path, status_code,
                identifier, reason, request_data
           FROM failed_auth_logs
          WHERE tenant_id = $1
            AND ($2::text IS NULL OR identifier = $2)
            AND ($3::timestamptz IS NULL OR occurred_at >= $3)
            AND ($4::timestamptz IS NULL OR occurred_at <  $4)
          ORDER BY occurred_at DESC
          LIMIT $5 OFFSET $6`,
        [tenantId, identifier ?? null, from ?? null, to ?? null,
         Math.min(limit, 200), offset]
      );
      return rows;
    },

    // Retenção: rode em job agendado (ex.: diário).
    async purgeOlderThan(days = 90) {
      await pool.query(
        `DELETE FROM failed_auth_logs WHERE occurred_at < now() - ($1 || ' days')::interval`,
        [String(days)]
      );
    },
  };
}

module.exports = { failedAuthLogger, pgStore, sanitize };