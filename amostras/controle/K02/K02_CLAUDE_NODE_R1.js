'use strict';

/**
 * Middleware CORS com credenciais para a API pública da plataforma SaaS.
 *
 * Princípios de segurança (OWASP Top 10):
 *  - A01 Broken Access Control: allowlist estrita de origens; nunca reflete o
 *    valor de Origin recebido, nunca usa "*" com credenciais, rejeita "null".
 *    Métodos não seguros vindos de origem não autorizada são bloqueados (403)
 *    como defesa em profundidade contra CSRF.
 *  - A02/A05 Security Misconfiguration: configuração validada na inicialização
 *    (falha rápida); métodos/headers permitidos vêm apenas da configuração;
 *    Vary correto para impedir envenenamento de cache.
 *  - A03 Injection: o único valor de requisição ecoado em header é uma origem
 *    que já foi validada e é idêntica a uma entrada da allowlist.
 *  - A04 Insecure Design: lista dinâmica (por tenant) em cache com TTL,
 *    single-flight e "stale-on-error"; origens aleatórias enviadas por um
 *    atacante nunca geram consulta ao banco.
 *  - A09 Logging Failures: hook onDenied com valores sanitizados.
 *  - Fail closed: qualquer erro resulta em negação.
 *
 * Uso (Express):
 *
 *   const { createCors } = require('./cors');
 *
 *   app.use(createCors({
 *     origins: ['https://app.plataforma.com', 'https://admin.plataforma.com'],
 *     // Opcional: origens de domínios próprios de clientes, já verificados
 *     getOrigins: async () => {
 *       const rows = await db.query(
 *         "SELECT origin FROM tenant_allowed_origins WHERE verified = true AND revoked_at IS NULL"
 *       );
 *       return rows.map(r => r.origin);
 *     },
 *     allowedHeaders: ['content-type', 'x-csrf-token'],
 *     onDenied: (info) => logger.warn({ cors: info }, 'CORS negado'),
 *     onError: (err) => logger.error({ err }, 'Falha ao carregar origens CORS'),
 *   }));
 *
 * Posicione ANTES da autenticação, do rate limiting por usuário e das rotas:
 * o preflight não carrega credenciais e deve ser respondido aqui.
 */

const MAX_ORIGIN_LENGTH = 255;
const MAX_REQUEST_HEADERS_LENGTH = 1024;
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const METHOD_RE = /^[A-Z]{3,10}$/;
const HEADER_NAME_RE = /^[a-z0-9-]{1,64}$/;
const FORBIDDEN_METHODS = new Set(['CONNECT', 'TRACE']);
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const DEFAULTS = Object.freeze({
  origins: [],
  getOrigins: null,
  cacheTtlMs: 60_000,
  allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['content-type', 'x-csrf-token', 'x-request-id'],
  exposedHeaders: [],
  maxAgeSeconds: 600,
  allowInsecureLocalhost: false, // habilitar somente em desenvolvimento
  onDenied: () => {},
  onError: () => {},
});

/**
 * Valida que `value` é uma origem canônica (esquema + host [+ porta]).
 * Exige igualdade com URL.origin, o que rejeita: "null", caminhos, userinfo,
 * porta padrão explícita, maiúsculas, curingas e formatos não canônicos.
 * Retorna a origem ou null.
 */
function parseOrigin(value, allowInsecureLocalhost = false) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ORIGIN_LENGTH) {
    return null;
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.origin !== value) return null;
  if (url.protocol === 'https:') return value;
  if (allowInsecureLocalhost && url.protocol === 'http:' && LOCAL_HOSTS.has(url.hostname)) {
    return value;
  }
  return null;
}

function sanitizeForLog(value) {
  return String(value ?? '').replace(/[^\x20-\x7E]/g, '?').slice(0, 100);
}

function appendVary(res, ...fields) {
  const current = res.getHeader('Vary');
  const parts = current ? String(current).split(',').map((s) => s.trim()).filter(Boolean) : [];
  const lower = new Set(parts.map((s) => s.toLowerCase()));
  if (lower.has('*')) return;
  for (const f of fields) {
    if (!lower.has(f.toLowerCase())) parts.push(f);
  }
  res.setHeader('Vary', parts.join(', '));
}

function parseRequestedHeaders(value) {
  if (value === undefined || value === '') return [];
  if (typeof value !== 'string' || value.length > MAX_REQUEST_HEADERS_LENGTH) return null;
  const out = [];
  for (const raw of value.split(',')) {
    const name = raw.trim().toLowerCase();
    if (!name) continue;
    if (!HEADER_NAME_RE.test(name)) return null;
    out.push(name);
  }
  return out;
}

function deny(res) {
  if (res.headersSent) return;
  res.statusCode = 403;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(JSON.stringify({ error: 'origin_not_allowed' }));
}

/**
 * Repositório de origens permitidas: lista estática (validada na inicialização)
 * + lista dinâmica opcional, atualizada de forma lazy com TTL.
 * `has()` nunca lança exceção.
 */
function createOriginStore({ origins, getOrigins, cacheTtlMs, allowInsecureLocalhost, onError }) {
  const staticSet = new Set();
  for (const o of origins) {
    const canonical = parseOrigin(o, allowInsecureLocalhost);
    if (!canonical) {
      throw new TypeError(`CORS: origem inválida na configuração: "${sanitizeForLog(o)}"`);
    }
    staticSet.add(canonical);
  }

  let dynamicSet = new Set();
  let expiresAt = 0;
  let inflight = null;

  async function refresh() {
    try {
      const list = await getOrigins();
      const next = new Set();
      for (const o of list) {
        const canonical = parseOrigin(o, allowInsecureLocalhost);
        if (canonical) {
          next.add(canonical);
        } else {
          onError(new Error(`CORS: origem dinâmica inválida ignorada: "${sanitizeForLog(o)}"`));
        }
      }
      dynamicSet = next;
      expiresAt = Date.now() + cacheTtlMs;
    } catch (err) {
      // Mantém a última lista válida (stale-on-error) e tenta de novo em breve,
      // sem sobrecarregar o banco.
      onError(err);
      expiresAt = Date.now() + Math.min(cacheTtlMs, 5_000);
    } finally {
      inflight = null;
    }
  }

  async function has(origin) {
    try {
      const canonical = parseOrigin(origin, allowInsecureLocalhost);
      if (!canonical) return false;
      if (staticSet.has(canonical)) return true;
      if (typeof getOrigins !== 'function') return false;
      if (Date.now() >= expiresAt) {
        inflight ??= refresh(); // single-flight
        await inflight;
      }
      return dynamicSet.has(canonical);
    } catch (err) {
      onError(err);
      return false; // fail closed
    }
  }

  return { has };
}

function validateConfig(options) {
  const cfg = { ...DEFAULTS, ...options };

  if (!Array.isArray(cfg.origins)) throw new TypeError('CORS: "origins" deve ser um array');
  if (cfg.getOrigins !== null && typeof cfg.getOrigins !== 'function') {
    throw new TypeError('CORS: "getOrigins" deve ser uma função');
  }
  if (cfg.origins.length === 0 && !cfg.getOrigins) {
    throw new TypeError('CORS: informe "origins" e/ou "getOrigins" (nenhuma origem configurada)');
  }
  if (!Number.isInteger(cfg.cacheTtlMs) || cfg.cacheTtlMs < 1_000) {
    throw new TypeError('CORS: "cacheTtlMs" deve ser inteiro >= 1000');
  }

  const methods = cfg.allowedMethods.map((m) => String(m).toUpperCase());
  for (const m of methods) {
    if (!METHOD_RE.test(m) || FORBIDDEN_METHODS.has(m)) {
      throw new TypeError(`CORS: método não permitido na configuração: "${sanitizeForLog(m)}"`);
    }
  }

  const headers = cfg.allowedHeaders.map((h) => String(h).toLowerCase());
  const exposed = cfg.exposedHeaders.map((h) => String(h).toLowerCase());
  for (const h of [...headers, ...exposed]) {
    if (h === '*' || !HEADER_NAME_RE.test(h)) {
      throw new TypeError(`CORS: nome de header inválido na configuração: "${sanitizeForLog(h)}"`);
    }
  }

  // Limite alinhado ao teto dos navegadores (Chromium: 7200s).
  const maxAge = Math.min(Math.max(Number(cfg.maxAgeSeconds) || 0, 0), 7200);

  return {
    ...cfg,
    methods: new Set(methods),
    methodsList: [...new Set(methods)].join(', '),
    headers: new Set(headers),
    headersList: [...new Set(headers)].join(', '),
    exposedList: [...new Set(exposed)].join(', '),
    maxAge,
  };
}

function createCors(options = {}) {
  const cfg = validateConfig(options);
  const store = createOriginStore({
    origins: cfg.origins,
    getOrigins: cfg.getOrigins,
    cacheTtlMs: cfg.cacheTtlMs,
    allowInsecureLocalhost: cfg.allowInsecureLocalhost,
    onError: cfg.onError,
  });

  function setAllowOrigin(res, origin) {
    // `origin` já foi validado e é idêntico a uma entrada da allowlist.
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  return async function corsMiddleware(req, res, next) {
    try {
      // Cache/CDN nunca deve servir a resposta de uma origem para outra.
      appendVary(res, 'Origin');

      const origin = req.headers.origin;
      if (origin === undefined) return next(); // não é requisição CORS

      const method = String(req.method).toUpperCase();
      const requestedMethod = req.headers['access-control-request-method'];
      const isPreflight = method === 'OPTIONS' && requestedMethod !== undefined;
      if (isPreflight) {
        appendVary(res, 'Access-Control-Request-Method', 'Access-Control-Request-Headers');
      }

      const allowed = await store.has(origin);

      if (!allowed) {
        cfg.onDenied({ reason: 'origin', origin: sanitizeForLog(origin), method, preflight: isPreflight });
        // Preflight e métodos que alteram estado de origem desconhecida: 403.
        // Leituras seguem sem headers CORS (o navegador bloqueia o acesso).
        if (isPreflight || !SAFE_METHODS.has(method)) return deny(res);
        return next();
      }

      if (isPreflight) {
        const requestedHeaders = parseRequestedHeaders(req.headers['access-control-request-headers']);
        const methodOk = typeof requestedMethod === 'string' && cfg.methods.has(requestedMethod);
        const headersOk = requestedHeaders !== null && requestedHeaders.every((h) => cfg.headers.has(h));

        if (!methodOk || !headersOk) {
          cfg.onDenied({
            reason: !methodOk ? 'method' : 'headers',
            origin: sanitizeForLog(origin),
            method: sanitizeForLog(requestedMethod),
            preflight: true,
          });
          return deny(res);
        }

        setAllowOrigin(res, origin);
        res.setHeader('Access-Control-Allow-Methods', cfg.methodsList);
        if (cfg.headersList) res.setHeader('Access-Control-Allow-Headers', cfg.headersList);
        res.setHeader('Access-Control-Max-Age', String(cfg.maxAge));
        res.setHeader('Content-Length', '0');
        res.statusCode = 204;
        return res.end();
      }

      setAllowOrigin(res, origin);
      if (cfg.exposedList) res.setHeader('Access-Control-Expose-Headers', cfg.exposedList);
      return next();
    } catch (err) {
      cfg.onError(err);
      return deny(res); // fail closed
    }
  };
}

module.exports = { createCors, parseOrigin };