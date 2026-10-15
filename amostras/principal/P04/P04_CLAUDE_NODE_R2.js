'use strict';

/**
 * Middleware de CORS para a API pública da plataforma SaaS multilocatária.
 *
 * Objetivo: permitir que aplicações web hospedadas em outros domínios consumam
 * a API enviando as credenciais de sessão (cookies) do usuário.
 *
 * Princípios de segurança:
 *  1. Com `Access-Control-Allow-Credentials: true` NUNCA se usa "*" nem se
 *     reflete a origem cegamente. Só origens previamente cadastradas passam.
 *  2. A origem é validada de forma estrita (parse via URL, comparação exata).
 *  3. `Vary: Origin` sempre presente, para caches/CDN não misturarem respostas.
 *  4. Falha fechada: erro na consulta de origens => origem não autorizada.
 *  5. Preflight (OPTIONS) é respondido aqui e não chega à camada de
 *     autenticação (o navegador não envia cookies no preflight).
 *
 * Compatível com Express/Connect e com o módulo http nativo
 * (assinatura (req, res, next)).
 */

const DEFAULT_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];

// Cabeçalhos que o front-end pode enviar. Inclui o identificador do tenant
// (caso o cliente o envie por cabeçalho) e o token anti-CSRF.
const DEFAULT_ALLOWED_HEADERS = [
  'Content-Type',
  'Accept',
  'Authorization',
  'X-Requested-With',
  'X-CSRF-Token',
  'X-Tenant-Id',
  'Idempotency-Key',
];

const DEFAULT_EXPOSED_HEADERS = [
  'X-Request-Id',
  'X-RateLimit-Limit',
  'X-RateLimit-Remaining',
  'X-RateLimit-Reset',
  'Retry-After',
];

/* -------------------------------------------------------------------------- */
/* Utilitários                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Normaliza e valida o valor do cabeçalho Origin.
 * Retorna a origem canônica (esquema://host[:porta]) ou null se inválida.
 * O valor literal "null" (iframes sandbox, file://, redirects) é rejeitado.
 */
function normalizeOrigin(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) {
    return null;
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (url.username || url.password) return null;
  // O cabeçalho Origin não tem caminho, query nem fragmento: exige igualdade exata.
  if (url.origin !== value.toLowerCase()) return null;
  return url.origin;
}

/**
 * Converte padrões como "https://*.cliente.com.br" em um verificador.
 * O curinga só é aceito como primeiro rótulo do host (subdomínios).
 */
function compileWildcard(pattern) {
  const match = /^(https?):\/\/\*\.([a-z0-9.-]+)(?::(\d+))?$/i.exec(pattern);
  if (!match) return null;
  const [, protocol, baseHost, port] = match;
  const suffix = '.' + baseHost.toLowerCase();
  // Exige ao menos dois rótulos no domínio-base (evita "*.com").
  if (baseHost.split('.').length < 2) return null;

  return (origin) => {
    const url = new URL(origin);
    return (
      url.protocol === protocol.toLowerCase() + ':' &&
      url.port === (port || '') &&
      url.hostname.endsWith(suffix) &&
      url.hostname.length > suffix.length
    );
  };
}

function addVary(res, field) {
  const current = res.getHeader('Vary');
  if (!current) {
    res.setHeader('Vary', field);
    return;
  }
  const list = String(current).split(',').map((s) => s.trim().toLowerCase());
  if (!list.includes('*') && !list.includes(field.toLowerCase())) {
    res.setHeader('Vary', `${current}, ${field}`);
  }
}

/** Cache em memória com TTL e tamanho máximo (evita crescimento ilimitado). */
class TtlCache {
  constructor(ttlMs, maxEntries = 5000) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.map = new Map();
  }
  get(key) {
    const hit = this.map.get(key);
    if (!hit) return undefined;
    if (hit.expiresAt < Date.now()) {
      this.map.delete(key);
      return undefined;
    }
    return hit.value;
  }
  set(key, value) {
    if (this.map.size >= this.maxEntries) {
      this.map.delete(this.map.keys().next().value); // descarta a mais antiga
    }
    this.map.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }
  clear() {
    this.map.clear();
  }
}

/* -------------------------------------------------------------------------- */
/* Middleware principal                                                       */
/* -------------------------------------------------------------------------- */

/**
 * @param {object}   options
 * @param {string[]} [options.staticOrigins]  Origens fixas (ex.: painel oficial
 *        da plataforma). Aceita curinga de subdomínio: "https://*.exemplo.com".
 * @param {(origin: string) => Promise<boolean>} [options.resolveOrigin]
 *        Consulta à base: a origem está cadastrada para algum tenant ativo
 *        (com plano de assinatura vigente)?
 * @param {boolean}  [options.allowInsecureLocalhost=false]  Aceita
 *        http://localhost[:porta] (apenas desenvolvimento).
 * @param {number}   [options.cacheTtlMs=60000]
 * @param {number}   [options.maxAgeSeconds=600]   Cache do preflight no navegador.
 * @param {string[]} [options.methods]
 * @param {string[]} [options.allowedHeaders]
 * @param {string[]} [options.exposedHeaders]
 * @param {(err: Error) => void} [options.onError]
 */
function createCorsMiddleware(options = {}) {
  const {
    staticOrigins = [],
    resolveOrigin = async () => false,
    allowInsecureLocalhost = false,
    cacheTtlMs = 60_000,
    maxAgeSeconds = 600,
    methods = DEFAULT_METHODS,
    allowedHeaders = DEFAULT_ALLOWED_HEADERS,
    exposedHeaders = DEFAULT_EXPOSED_HEADERS,
    onError = () => {},
  } = options;

  const exactOrigins = new Set();
  const wildcardMatchers = [];

  for (const entry of staticOrigins) {
    if (entry === '*') {
      throw new Error(
        'CORS: "*" é proibido com credenciais. Cadastre as origens explicitamente.'
      );
    }
    const wildcard = compileWildcard(entry);
    if (wildcard) {
      wildcardMatchers.push(wildcard);
      continue;
    }
    const normalized = normalizeOrigin(entry);
    if (!normalized) throw new Error(`CORS: origem estática inválida: ${entry}`);
    exactOrigins.add(normalized);
  }

  const cache = new TtlCache(cacheTtlMs);
  const allowedMethodsSet = new Set(methods.map((m) => m.toUpperCase()));
  const allowedHeadersSet = new Set(allowedHeaders.map((h) => h.toLowerCase()));
  const allowMethodsHeader = methods.join(', ');
  const allowHeadersHeader = allowedHeaders.join(', ');
  const exposeHeadersHeader = exposedHeaders.join(', ');

  function isLocalhost(origin) {
    const { protocol, hostname } = new URL(origin);
    return protocol === 'http:' && (hostname === 'localhost' || hostname === '127.0.0.1');
  }

  async function isOriginAllowed(origin) {
    // Em produção só HTTPS (evita cookies Secure vazando em canal inseguro).
    if (origin.startsWith('http://') && !(allowInsecureLocalhost && isLocalhost(origin))) {
      return false;
    }
    if (exactOrigins.has(origin)) return true;
    if (wildcardMatchers.some((match) => match(origin))) return true;

    const cached = cache.get(origin);
    if (cached !== undefined) return cached;

    try {
      const allowed = (await resolveOrigin(origin)) === true;
      cache.set(origin, allowed);
      return allowed;
    } catch (err) {
      onError(err);
      return false; // falha fechada (e sem cachear o erro)
    }
  }

  function reject(res) {
    res.statusCode = 403;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'CORS_ORIGIN_NOT_ALLOWED' }));
  }

  const middleware = async function cors(req, res, next) {
    const rawOrigin = req.headers.origin;

    // Sem Origin: requisição same-origin ou cliente não-navegador (curl, server-to-server).
    if (rawOrigin === undefined) return next();

    // As respostas variam conforme a origem: indispensável para caches/CDN.
    addVary(res, 'Origin');

    const isPreflight =
      req.method === 'OPTIONS' && req.headers['access-control-request-method'] !== undefined;

    if (isPreflight) {
      addVary(res, 'Access-Control-Request-Method');
      addVary(res, 'Access-Control-Request-Headers');
    }

    const origin = normalizeOrigin(rawOrigin);
    const allowed = origin !== null && (await isOriginAllowed(origin));

    if (!allowed) {
      // Não emite nenhum cabeçalho CORS: o navegador bloqueia a leitura da resposta.
      if (isPreflight) return reject(res);
      return next();
    }

    // Cabeçalhos comuns a preflight e requisição real.
    res.setHeader('Access-Control-Allow-Origin', origin); // origem específica, nunca "*"
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (!isPreflight) {
      if (exposeHeadersHeader) {
        res.setHeader('Access-Control-Expose-Headers', exposeHeadersHeader);
      }
      return next();
    }

    // --- Preflight ---------------------------------------------------------
    const requestedMethod = String(req.headers['access-control-request-method']).toUpperCase();
    if (!allowedMethodsSet.has(requestedMethod)) return reject(res);

    const requestedHeaders = String(req.headers['access-control-request-headers'] || '')
      .split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean);
    if (!requestedHeaders.every((h) => allowedHeadersSet.has(h))) return reject(res);

    res.setHeader('Access-Control-Allow-Methods', allowMethodsHeader);
    res.setHeader('Access-Control-Allow-Headers', allowHeadersHeader);
    res.setHeader('Access-Control-Max-Age', String(maxAgeSeconds));
    res.statusCode = 204;
    res.setHeader('Content-Length', '0');
    return res.end();
  };

  // Permite invalidar o cache quando um tenant altera suas origens no painel.
  middleware.invalidateCache = () => cache.clear();
  return middleware;
}

/* -------------------------------------------------------------------------- */
/* Camada extra (opcional): vínculo origem <-> tenant após autenticação       */
/* -------------------------------------------------------------------------- */

/**
 * Executar DEPOIS da autenticação. Garante que a origem que enviou a requisição
 * com cookie de sessão pertence ao tenant do usuário autenticado, evitando que
 * um site cadastrado por uma empresa use a sessão de usuário de outra empresa.
 *
 * @param {(tenantId: string) => Promise<string[]>} getTenantOrigins
 *        Retorna as origens normalizadas cadastradas para o tenant.
 */
function requireTenantOrigin(getTenantOrigins) {
  return async function tenantOriginGuard(req, res, next) {
    const rawOrigin = req.headers.origin;
    if (rawOrigin === undefined) return next();

    const origin = normalizeOrigin(rawOrigin);
    const tenantId = req.user && req.user.tenantId;
    if (!origin || !tenantId) return next();

    try {
      const origins = await getTenantOrigins(tenantId);
      if (origins.includes(origin)) return next();
    } catch (err) {
      return next(err);
    }

    res.statusCode = 403;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    return res.end(JSON.stringify({ error: 'ORIGIN_NOT_ALLOWED_FOR_TENANT' }));
  };
}

module.exports = { createCorsMiddleware, requireTenantOrigin, normalizeOrigin };

/* -------------------------------------------------------------------------- */
/* Exemplo de uso (Express)                                                   */
/* -------------------------------------------------------------------------- */
/*
const express = require('express');
const { createCorsMiddleware, requireTenantOrigin } = require('./cors.middleware');
const db = require('./db'); // sua camada de acesso a dados

const app = express();

const cors = createCorsMiddleware({
  staticOrigins: ['https://app.plataforma.com.br', 'https://*.plataforma.com.br'],
  allowInsecureLocalhost: process.env.NODE_ENV !== 'production',
  // Origens cadastradas pelos tenants com assinatura ativa.
  resolveOrigin: async (origin) => {
    const { rows } = await db.query(
      `SELECT 1
         FROM tenant_allowed_origins o
         JOIN subscriptions s ON s.tenant_id = o.tenant_id
        WHERE o.origin = $1 AND s.status = 'active'
        LIMIT 1`,
      [origin]
    );
    return rows.length > 0;
  },
  onError: (err) => console.error('[cors] falha ao consultar origens', err),
});

// CORS deve ser o PRIMEIRO middleware: antes de autenticação, rate limit e rotas.
app.use(cors);
app.use(express.json());
app.use(authenticate); // popula req.user = { id, tenantId, ... }
app.use(requireTenantOrigin(async (tenantId) => {
  const { rows } = await db.query(
    'SELECT origin FROM tenant_allowed_origins WHERE tenant_id = $1',
    [tenantId]
  );
  return rows.map((r) => r.origin);
}));

// Ao alterar origens de um tenant: cors.invalidateCache();
*/