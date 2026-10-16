'use strict';

/**
 * Middleware CORS para a API pública (SaaS multilocatário).
 *
 * Princípios de segurança aplicados (OWASP A01, A05, A07):
 *  - Allowlist explícita e por correspondência EXATA de origem (nunca regex frouxa,
 *    nunca "endsWith", nunca reflexão cega do header Origin).
 *  - Nunca usa "*" junto com credenciais.
 *  - Rejeita a origem "null" (iframes sandbox, file://, redirecionamentos).
 *  - Exige HTTPS (http apenas para localhost, e somente fora de produção).
 *  - Falha fechada: erro ao consultar origens permitidas => sem headers CORS.
 *  - Vary: Origin sempre presente (evita envenenamento de cache/CDN).
 *  - Métodos e headers restritos a uma lista; preflight valida o que foi solicitado.
 */

const DEFAULTS = Object.freeze({
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
  exposedHeaders: ['X-Request-Id', 'Retry-After'],
  maxAge: 600, // segundos
  credentials: true,
  allowInsecureLocalhost: process.env.NODE_ENV !== 'production',
});

const MAX_ORIGIN_LENGTH = 256;

function normalizeOrigin(value, allowInsecureLocalhost) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ORIGIN_LENGTH) return null;
  if (value === 'null') return null;

  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }

  const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  const protocolOk =
    url.protocol === 'https:' || (allowInsecureLocalhost && isLocalhost && url.protocol === 'http:');
  if (!protocolOk) return null;

  // Origem válida não possui path, query, hash nem credenciais embutidas.
  if (url.origin !== value) return null;

  return url.origin;
}

/**
 * @param {object} options
 * @param {string[]} [options.staticOrigins]  Origens fixas confiáveis (ex.: painel da própria plataforma).
 * @param {(origin: string, req: object) => Promise<boolean>|boolean} [options.isOriginAllowed]
 *        Consulta dinâmica (ex.: domínios cadastrados pelas empresas clientes, com cache).
 */
function createCors(options = {}) {
  const cfg = { ...DEFAULTS, ...options };
  const methods = new Set(cfg.methods.map((m) => m.toUpperCase()));
  const allowedHeaders = new Set(cfg.allowedHeaders.map((h) => h.toLowerCase()));

  const staticOrigins = new Set(
    (cfg.staticOrigins || [])
      .map((o) => normalizeOrigin(o, cfg.allowInsecureLocalhost))
      .filter(Boolean)
  );

  async function originAllowed(origin, req) {
    if (staticOrigins.has(origin)) return true;
    if (typeof cfg.isOriginAllowed !== 'function') return false;
    try {
      return (await cfg.isOriginAllowed(origin, req)) === true;
    } catch {
      return false; // falha fechada
    }
  }

  function appendVary(res, value) {
    const current = res.getHeader('Vary');
    const list = current ? String(current).split(',').map((v) => v.trim().toLowerCase()) : [];
    if (!list.includes(value.toLowerCase())) {
      res.setHeader('Vary', current ? `${current}, ${value}` : value);
    }
  }

  return async function corsMiddleware(req, res, next) {
    appendVary(res, 'Origin');

    const rawOrigin = req.headers.origin;

    // Requisição sem Origin (server-to-server, curl, mesma origem): CORS não se aplica.
    if (rawOrigin === undefined) return next();

    const origin = normalizeOrigin(rawOrigin, cfg.allowInsecureLocalhost);
    const allowed = origin !== null && (await originAllowed(origin, req));

    const isPreflight =
      req.method === 'OPTIONS' && req.headers['access-control-request-method'] !== undefined;

    if (!allowed) {
      // Sem headers CORS: o navegador bloqueia a leitura da resposta.
      if (isPreflight) {
        res.statusCode = 403;
        return res.end();
      }
      return next();
    }

    res.setHeader('Access-Control-Allow-Origin', origin); // origem validada, nunca "*"
    if (cfg.credentials) res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (!isPreflight) {
      if (cfg.exposedHeaders.length) {
        res.setHeader('Access-Control-Expose-Headers', cfg.exposedHeaders.join(', '));
      }
      return next();
    }

    // ---- Preflight ----
    appendVary(res, 'Access-Control-Request-Method');
    appendVary(res, 'Access-Control-Request-Headers');

    const reqMethod = String(req.headers['access-control-request-method']).toUpperCase();
    if (!methods.has(reqMethod)) {
      res.statusCode = 405;
      return res.end();
    }

    const reqHeadersRaw = req.headers['access-control-request-headers'];
    if (reqHeadersRaw) {
      const requested = String(reqHeadersRaw)
        .split(',')
        .map((h) => h.trim().toLowerCase())
        .filter(Boolean);
      if (!requested.every((h) => allowedHeaders.has(h))) {
        res.statusCode = 403;
        return res.end();
      }
    }

    res.setHeader('Access-Control-Allow-Methods', [...methods].join(', '));
    res.setHeader('Access-Control-Allow-Headers', cfg.allowedHeaders.join(', '));
    res.setHeader('Access-Control-Max-Age', String(cfg.maxAge));
    res.statusCode = 204;
    return res.end();
  };
}

module.exports = { createCors, normalizeOrigin };