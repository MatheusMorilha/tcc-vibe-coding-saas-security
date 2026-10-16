'use strict';

/**
 * failed-auth-logger.js
 *
 * Registra tentativas de autenticação malsucedidas para consulta posterior pelo suporte.
 *
 * Variáveis de ambiente (obrigatórias, a aplicação não sobe sem elas):
 *   FAILED_AUTH_ENC_KEY   -> 32 bytes em base64 (AES-256-GCM, cifra o snapshot da requisição)
 *   FAILED_AUTH_HMAC_KEY  -> 32+ bytes em base64 (HMAC do identificador, permite busca sem texto claro)
 *
 * Uso:
 *   app.set('trust proxy', <config correta do seu proxy>);   // senão req.ip pode ser forjado
 *   app.post('/auth/login',
 *     express.json({ limit: '10kb' }),                        // o logger vem DEPOIS do body parser
 *     failedAuthLogger({ store, encKey, hmacKey }),
 *     loginHandler);                                          // o handler responde 401 (ou define res.locals.authFailure)
 *
 * SQL (PostgreSQL):
 *
 *   CREATE TABLE failed_auth_log (
 *     id              BIGSERIAL PRIMARY KEY,
 *     occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
 *     request_id      VARCHAR(64) NOT NULL,
 *     tenant_id       VARCHAR(64),            -- INFORMADO pelo cliente (não autenticado): não é confiável
 *     identifier_hash CHAR(64),               -- HMAC-SHA256 do login informado
 *     ip              VARCHAR(45),
 *     user_agent      VARCHAR(256),
 *     method          VARCHAR(10) NOT NULL,
 *     path            VARCHAR(256) NOT NULL,
 *     status_code     SMALLINT NOT NULL,
 *     reason          VARCHAR(64),
 *     snapshot_enc    TEXT NOT NULL           -- headers/query/body já redigidos, cifrados
 *   );
 *   CREATE INDEX ON failed_auth_log (tenant_id, occurred_at DESC);
 *   CREATE INDEX ON failed_auth_log (identifier_hash, occurred_at DESC);
 *   CREATE INDEX ON failed_auth_log (ip, occurred_at DESC);
 *   -- Retenção: job diário  DELETE FROM failed_auth_log WHERE occurred_at < now() - interval '90 days';
 *   -- Permissões: o usuário do banco usado pela API só precisa de INSERT (escrita) e SELECT na rota de suporte.
 */

const crypto = require('node:crypto');

// ---------------------------------------------------------------------------
// Configuração de sanitização
// ---------------------------------------------------------------------------
const SENSITIVE_KEY =
  /pass(word|wd|phrase)?|senha|secret|token|authorization|auth|cookie|session|api[-_]?key|otp|totp|mfa|code|codigo|pin|cvv|card|cartao|jwt|credential|assertion|signature|private|bearer|csrf|xsrf/i;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const HEADER_ALLOWLIST = [
  'user-agent', 'origin', 'referer', 'accept', 'accept-language',
  'content-type', 'content-length', 'x-request-id', 'x-tenant-id',
];
const LIMITS = { depth: 4, keys: 40, array: 20, string: 256, snapshotBytes: 8 * 1024 };
const REDACTED = '[REDACTED]';
const TENANT_FORMAT = /^[A-Za-z0-9_-]{1,64}$/;
const REQUEST_ID_FORMAT = /^[A-Za-z0-9_-]{1,64}$/;

// Remove caracteres de controle (evita log injection / forjamento de linhas) e limita tamanho.
function cleanString(value, max = LIMITS.string) {
  return String(value)
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ')
    .slice(0, max);
}

// Redação profunda e limitada: nunca grava valores de chaves sensíveis, nem parcialmente.
function redact(value, depth = 0) {
  if (value === null || value === undefined) return value ?? null;
  if (typeof value === 'string') return cleanString(value);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth >= LIMITS.depth) return '[TRUNCATED]';

  if (Array.isArray(value)) {
    return value.slice(0, LIMITS.array).map((v) => redact(v, depth + 1));
  }
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).slice(0, LIMITS.keys)) {
      if (FORBIDDEN_KEYS.has(key)) continue;
      const safeKey = cleanString(key, 64);
      out[safeKey] = SENSITIVE_KEY.test(key) ? REDACTED : redact(value[key], depth + 1);
    }
    return out;
  }
  return '[UNSUPPORTED]';
}

function redactHeaders(headers) {
  const out = {};
  for (const name of HEADER_ALLOWLIST) {
    if (headers[name] === undefined) continue;
    let v = String(headers[name]);
    if (name === 'referer' || name === 'origin') v = v.split(/[?#]/)[0]; // query pode conter tokens
    out[name] = cleanString(v);
  }
  return out;
}

function redactQuery(rawUrl) {
  const idx = rawUrl.indexOf('?');
  if (idx === -1) return {};
  const out = {};
  let n = 0;
  for (const [k, v] of new URLSearchParams(rawUrl.slice(idx + 1))) {
    if (n++ >= LIMITS.keys) break;
    if (FORBIDDEN_KEYS.has(k)) continue;
    out[cleanString(k, 64)] = SENSITIVE_KEY.test(k) ? REDACTED : cleanString(v);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Criptografia e hash
// ---------------------------------------------------------------------------
function loadKey(b64, name, minBytes = 32) {
  const key = Buffer.from(b64 || '', 'base64');
  if (key.length < minBytes) throw new Error(`${name} ausente ou inválida (mínimo ${minBytes} bytes em base64)`);
  return key;
}

function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key.subarray(0, 32), iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return ['v1', iv, cipher.getAuthTag(), ct].map((p) => (Buffer.isBuffer(p) ? p.toString('base64') : p)).join('.');
}

function decrypt(payload, key) {
  const [version, iv, tag, ct] = String(payload).split('.');
  if (version !== 'v1') throw new Error('versão de snapshot desconhecida');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key.subarray(0, 32), Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(ct, 'base64')), decipher.final()]).toString('utf8');
}

function hashIdentifier(identifier, hmacKey) {
  // Normaliza para que "Fulano@X.com " e "fulano@x.com" gerem o mesmo hash.
  return crypto.createHmac('sha256', hmacKey).update(String(identifier).trim().toLowerCase()).digest('hex');
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
const defaultIsFailure = (req, res) => Boolean(res.locals && res.locals.authFailure) || res.statusCode === 401;

const defaultGetTenantId = (req) => {
  const raw = (req.body && req.body.tenant) || req.headers['x-tenant-id'];
  return typeof raw === 'string' && TENANT_FORMAT.test(raw) ? raw : null;
};

function failedAuthLogger({
  store,
  encKey,
  hmacKey,
  identifierFields = ['email', 'username', 'login'],
  getTenantId = defaultGetTenantId,
  isFailure = defaultIsFailure,
} = {}) {
  if (!store || typeof store.insert !== 'function') throw new TypeError('store.insert é obrigatório');
  const encryptionKey = loadKey(encKey, 'FAILED_AUTH_ENC_KEY');
  const identifierKey = loadKey(hmacKey, 'FAILED_AUTH_HMAC_KEY');

  return function failedAuthLoggerMiddleware(req, res, next) {
    // Registra APÓS a resposta: não adiciona latência nem altera o fluxo de autenticação.
    res.on('finish', () => {
      let requestId = 'unknown';
      try {
        if (!isFailure(req, res)) return;

        const hdrId = req.headers['x-request-id'];
        requestId = req.id || (typeof hdrId === 'string' && REQUEST_ID_FORMAT.test(hdrId) ? hdrId : crypto.randomUUID());

        const body = req.body && typeof req.body === 'object' ? req.body : {};
        const rawIdentifier = identifierFields.map((f) => body[f]).find((v) => typeof v === 'string' && v.length > 0);

        let snapshot = JSON.stringify({
          headers: redactHeaders(req.headers),
          query: redactQuery(req.originalUrl || req.url || ''),
          body: redact(body),
        });
        if (Buffer.byteLength(snapshot) > LIMITS.snapshotBytes) {
          snapshot = JSON.stringify({ truncated: true, note: 'snapshot excedeu o limite' });
        }

        const record = {
          requestId,
          tenantId: getTenantId(req),
          identifierHash: rawIdentifier ? hashIdentifier(cleanString(rawIdentifier, 254), identifierKey) : null,
          ip: cleanString(req.ip || '', 45),
          userAgent: cleanString(req.headers['user-agent'] || '', 256),
          method: cleanString(req.method, 10),
          path: cleanString((req.originalUrl || req.url || '').split('?')[0], 256),
          statusCode: res.statusCode,
          reason: cleanString((res.locals && res.locals.authFailure && res.locals.authFailure.reason) || 'invalid_credentials', 64),
          snapshotEnc: encrypt(snapshot, encryptionKey),
        };

        Promise.resolve(store.insert(record)).catch((err) => logInternalError(requestId, err));
      } catch (err) {
        logInternalError(requestId, err);
      }
    });
    next();
  };
}

// Falha de log nunca derruba a requisição e nunca imprime dados da requisição (A09).
function logInternalError(requestId, err) {
  process.stderr.write(
    JSON.stringify({ level: 'error', event: 'failed_auth_log_write_error', requestId, error: (err && (err.code || err.name)) || 'unknown' }) + '\n'
  );
}

// ---------------------------------------------------------------------------
// Repositório PostgreSQL (somente queries parametrizadas)
// ---------------------------------------------------------------------------
function createPostgresStore(pool) {
  return {
    async insert(r) {
      await pool.query(
        `INSERT INTO failed_auth_log
           (request_id, tenant_id, identifier_hash, ip, user_agent, method, path, status_code, reason, snapshot_enc)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [r.requestId, r.tenantId, r.identifierHash, r.ip, r.userAgent, r.method, r.path, r.statusCode, r.reason, r.snapshotEnc]
      );
    },

    async query({ tenantId, identifierHash, ip, from, to, limit = 50, offset = 0 }) {
      const where = [];
      const params = [];
      const add = (sql, value) => { params.push(value); where.push(sql.replace('?', `$${params.length}`)); };

      if (tenantId) add('tenant_id = ?', tenantId);
      if (identifierHash) add('identifier_hash = ?', identifierHash);
      if (ip) add('ip = ?', ip);
      if (from) add('occurred_at >= ?', from);
      if (to) add('occurred_at <= ?', to);

      params.push(Math.min(Math.max(Number(limit) || 50, 1), 100)); // teto de 100 por página
      params.push(Math.max(Number(offset) || 0, 0));
      const { rows } = await pool.query(
        `SELECT id, occurred_at, request_id, tenant_id, ip, user_agent, method, path, status_code, reason, snapshot_enc
           FROM failed_auth_log
          ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
          ORDER BY occurred_at DESC
          LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params
      );
      return rows;
    },
  };
}

// ---------------------------------------------------------------------------
// Handler de consulta para o suporte (A01: controle de acesso + auditoria do acesso)
// ---------------------------------------------------------------------------
/**
 * app.get('/internal/support/failed-auth',
 *   authenticateStaff,                          // sessão/SSO da equipe interna + MFA
 *   requireStaffRole(['support', 'security']),  // RBAC: usuário de tenant NUNCA acessa esta rota
 *   supportQueryHandler({ store, encKey, hmacKey, audit }));
 *
 * `audit(event)` deve gravar quem consultou, filtros usados e se o payload foi aberto.
 */
function supportQueryHandler({ store, encKey, hmacKey, audit }) {
  const encryptionKey = loadKey(encKey, 'FAILED_AUTH_ENC_KEY');
  const identifierKey = loadKey(hmacKey, 'FAILED_AUTH_HMAC_KEY');

  return async function (req, res) {
    try {
      const { tenantId, identifier, ip, from, to, limit, offset, includePayload } = req.query;

      if (tenantId !== undefined && !TENANT_FORMAT.test(String(tenantId))) return res.status(400).json({ error: 'tenantId inválido' });
      const fromDate = from ? new Date(String(from)) : undefined;
      const toDate = to ? new Date(String(to)) : undefined;
      if ((fromDate && isNaN(fromDate)) || (toDate && isNaN(toDate))) return res.status(400).json({ error: 'intervalo de datas inválido' });

      // O payload só é decifrado para quem tem perfil específico e a abertura fica auditada.
      const wantsPayload = includePayload === 'true' && Array.isArray(req.staff && req.staff.roles) && req.staff.roles.includes('security');

      const rows = await store.query({
        tenantId: tenantId && String(tenantId),
        identifierHash: identifier ? hashIdentifier(String(identifier).slice(0, 254), identifierKey) : undefined,
        ip: ip && String(ip).slice(0, 45),
        from: fromDate,
        to: toDate,
        limit,
        offset,
      });

      await audit({
        staffId: req.staff && req.staff.id,
        action: 'failed_auth_log.query',
        filters: { tenantId, ip, from, to, hasIdentifier: Boolean(identifier) },
        payloadOpened: wantsPayload,
        resultCount: rows.length,
      });

      res.set('Cache-Control', 'no-store');
      res.json(
        rows.map(({ snapshot_enc, ...meta }) => ({
          ...meta,
          ...(wantsPayload ? { snapshot: JSON.parse(decrypt(snapshot_enc, encryptionKey)) } : {}),
        }))
      );
    } catch (err) {
      logInternalError('support-query', err);
      res.status(500).json({ error: 'Erro interno' }); // sem detalhes internos ao cliente (A05)
    }
  };
}

module.exports = {
  failedAuthLogger,
  createPostgresStore,
  supportQueryHandler,
  // exportados para testes unitários
  _internals: { redact, redactHeaders, redactQuery, cleanString, encrypt, decrypt, hashIdentifier },
};