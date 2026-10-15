'use strict';

/**
 * Middleware de CORS para a API pública da plataforma SaaS multilocatária.
 *
 * Objetivo: permitir que aplicações web hospedadas em outros domínios consumam a API
 * enviando credenciais de sessão (cookies), sem abrir a API para qualquer origem.
 *
 * Princípios de segurança:
 *  1. Com credenciais, "Access-Control-Allow-Origin: *" é proibido pelo navegador e inseguro.
 *     Por isso a origem é validada contra uma lista e só então refletida, de forma exata.
 *  2. Origem "null", esquemas diferentes de http/https e valores malformados são rejeitados.
 *  3. "Vary: Origin" é sempre enviado, evitando que caches (CDN/proxy) sirvam a resposta
 *     de uma origem para outra.
 *  4. Falha fechada: erro ao consultar as origens permitidas => origem negada.
 *  5. Requisições com mutação (POST/PUT/PATCH/DELETE) vindas de origens não autorizadas
 *     são bloqueadas no servidor (o CORS sozinho não impede CSRF).
 *
 * Sem dependências externas. Compatível com Express/Connect e com http nativo (req, res, next).
 */

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const DEFAULTS = {
  methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'Authorization', 'X-Requested-With', 'X-CSRF-Token'],
  exposedHeaders: ['X-Request-Id', 'RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset', 'Retry-After'],
  maxAge: 600, // segundos (navegadores limitam o valor; Chromium aceita até 7200)
  cacheTtlMs: 60 * 1000, // cache de resultados positivos
  negativeCacheTtlMs: 15 * 1000, // cache de resultados negativos
  cacheMaxEntries: 5000, // teto para impedir crescimento de memória por origens aleatórias
  requireHttps: true,
  allowLocalhostHttp: false, // true apenas em desenvolvimento
  blockDisallowedUnsafeRequests: true,
};

/** Acrescenta um campo ao cabeçalho Vary sem sobrescrever valores existentes. */
function appendVary(res, field) {
  const current = res.getHeader('Vary');
  if (!current) {
    res.setHeader('Vary', field);
    return;
  }
  const tokens = String(current)
    .split(',')
    .map((t) => t.trim().toLowerCase());
  if (tokens.includes('*') || tokens.includes(field.toLowerCase())) return;
  res.setHeader('Vary', `${String(current)}, ${field}`);
}

function isLocalhost(hostname) {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

/**
 * Valida e normaliza o valor do cabeçalho Origin.
 * Retorna um objeto URL ou null se for inválido.
 */
function parseOrigin(raw, { requireHttps, allowLocalhostHttp }) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 255 || raw === 'null') return null;

  let url;
  try {
    url = new URL(raw);
  } catch (_) {
    return null;
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;

  // Uma origem válida é exatamente esquema://host[:porta], sem caminho, query, usuário etc.
  if (url.origin !== raw.toLowerCase()) return null;

  if (url.protocol === 'http:' && requireHttps) {
    if (!(allowLocalhostHttp && isLocalhost(url.hostname))) return null;
  }
  return url;
}

/**
 * Compila a lista estática de origens: aceita origens exatas
 * ("https://app.cliente.com") e curingas de subdomínio ("https://*.cliente.com").
 * O curinga exige ao menos um rótulo antes do domínio e respeita esquema e porta.
 */
function compileStaticOrigins(list) {
  const exact = new Set();
  const wildcards = [];

  for (const entry of list) {
    if (typeof entry !== 'string' || entry.trim() === '' || entry.trim() === '*') {
      throw new Error(`CORS: origem estática inválida (curinga global "*" não é permitido com credenciais): ${entry}`);
    }
    const value = entry.trim().toLowerCase();
    const wc = /^(https?):\/\/\*\.([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::(\d{1,5}))?$/.exec(value);
    if (wc) {
      wildcards.push({ protocol: `${wc[1]}:`, baseDomain: wc[2], port: wc[3] || '' });
      continue;
    }
    let url;
    try {
      url = new URL(value);
    } catch (_) {
      throw new Error(`CORS: origem estática inválida: ${entry}`);
    }
    if (url.origin !== value) throw new Error(`CORS: informe apenas esquema://host[:porta]: ${entry}`);
    exact.add(url.origin);
  }
  return { exact, wildcards };
}

function matchesStatic(url, compiled) {
  if (compiled.exact.has(url.origin)) return true;
  return compiled.wildcards.some(
    (w) => w.protocol === url.protocol && w.port === url.port && url.hostname.endsWith(`.${w.baseDomain}`)
  );
}

/**
 * Cria o middleware.
 *
 * @param {object}   options
 * @param {string[]} [options.staticOrigins]   Origens fixas (painel oficial, site institucional etc.).
 * @param {(origin: string, req: object) => Promise<boolean>|boolean} [options.isOriginAllowed]
 *        Consulta dinâmica das origens cadastradas pelos tenants. Como o preflight não carrega
 *        cookies, a decisão é tomada pela própria origem (e não pela sessão do usuário).
 * @param {(err: Error) => void} [options.onError]  Log de falhas na consulta dinâmica.
 */
function createCorsMiddleware(options = {}) {
  const cfg = { ...DEFAULTS, ...options };
  const staticCompiled = compileStaticOrigins(cfg.staticOrigins || []);
  const parseOpts = { requireHttps: cfg.requireHttps, allowLocalhostHttp: cfg.allowLocalhostHttp };

  const allowMethods = cfg.methods.join(', ');
  const allowHeaders = cfg.allowedHeaders.join(', ');
  const exposeHeaders = cfg.exposedHeaders.join(', ');
  const onError = typeof cfg.onError === 'function' ? cfg.onError : () => {};

  const cache = new Map(); // origem -> { allowed, expires }
  const pending = new Map(); // origem -> Promise<boolean> (evita avalanche de consultas)

  async function lookupDynamic(origin, req) {
    if (typeof cfg.isOriginAllowed !== 'function') return false;

    const now = Date.now();
    const hit = cache.get(origin);
    if (hit && hit.expires > now) return hit.allowed;
    if (pending.has(origin)) return pending.get(origin);

    const promise = (async () => {
      let allowed = false;
      try {
        allowed = (await cfg.isOriginAllowed(origin, req)) === true;
      } catch (err) {
        onError(err);
        return false; // falha fechada e sem cache
      }
      cache.delete(origin);
      cache.set(origin, {
        allowed,
        expires: Date.now() + (allowed ? cfg.cacheTtlMs : cfg.negativeCacheTtlMs),
      });
      if (cache.size > cfg.cacheMaxEntries) cache.delete(cache.keys().next().value);
      return allowed;
    })();

    pending.set(origin, promise);
    try {
      return await promise;
    } finally {
      pending.delete(origin);
    }
  }

  async function isAllowed(url, req) {
    if (matchesStatic(url, staticCompiled)) return true;
    return lookupDynamic(url.origin, req);
  }

  function reject(res, status, message) {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: message }));
  }

  async function cors(req, res, next) {
    try {
      // O resultado depende de Origin: sempre informe isso aos caches.
      appendVary(res, 'Origin');

      const originHeader = req.headers.origin;
      if (!originHeader) return next(); // chamadas servidor-a-servidor ou navegação same-origin

      const isPreflight = req.method === 'OPTIONS' && Boolean(req.headers['access-control-request-method']);
      if (isPreflight) {
        appendVary(res, 'Access-Control-Request-Method');
        appendVary(res, 'Access-Control-Request-Headers');
      }

      const url = parseOrigin(originHeader, parseOpts);
      const allowed = url ? await isAllowed(url, req) : false;

      if (!allowed) {
        // Sem cabeçalhos CORS: o navegador bloqueia a leitura da resposta.
        if (isPreflight) return reject(res, 403, 'Origem não autorizada.');

        const sameOrigin = url && url.host === req.headers.host;
        if (cfg.blockDisallowedUnsafeRequests && !SAFE_METHODS.has(req.method) && !sameOrigin) {
          return reject(res, 403, 'Origem não autorizada.');
        }
        return next();
      }

      // Origem autorizada: reflete exatamente a origem validada (nunca "*").
      res.setHeader('Access-Control-Allow-Origin', url.origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      if (exposeHeaders) res.setHeader('Access-Control-Expose-Headers', exposeHeaders);

      if (isPreflight) {
        res.setHeader('Access-Control-Allow-Methods', allowMethods);
        res.setHeader('Access-Control-Allow-Headers', allowHeaders);
        res.setHeader('Access-Control-Max-Age', String(cfg.maxAge));
        res.statusCode = 204;
        res.setHeader('Content-Length', '0');
        return res.end();
      }

      return next();
    } catch (err) {
      return next(err);
    }
  }

  /** Invalida o cache de uma origem (ou de todas) quando o tenant altera suas origens. */
  cors.invalidateCache = (origin) => {
    if (origin) cache.delete(String(origin).toLowerCase());
    else cache.clear();
  };

  return cors;
}

module.exports = { createCorsMiddleware };

/* ---------------------------------------------------------------------------
 * EXEMPLO DE USO (Express)
 *
 * const express = require('express');
 * const { createCorsMiddleware } = require('./cors-middleware');
 *
 * const app = express();
 * app.set('trust proxy', 1);
 *
 * const cors = createCorsMiddleware({
 *   staticOrigins: ['https://app.minhaplataforma.com', 'https://*.minhaplataforma.com'],
 *
 *   // Origens cadastradas pelos tenants. Só vale para empresas com assinatura ativa.
 *   isOriginAllowed: async (origin) => {
 *     const { rowCount } = await db.query(
 *       `SELECT 1
 *          FROM tenant_allowed_origins o
 *          JOIN tenants t       ON t.id = o.tenant_id
 *          JOIN subscriptions s ON s.tenant_id = t.id
 *         WHERE o.origin = $1 AND o.active = true AND t.active = true
 *           AND s.status = 'active'
 *         LIMIT 1`,
 *       [origin]
 *     );
 *     return rowCount > 0;
 *   },
 *   onError: (err) => logger.error({ err }, 'Falha ao consultar origens CORS'),
 * });
 *
 * // Deve ser o PRIMEIRO middleware: antes de parsers, autenticação, rate limit e rotas,
 * // para que erros 401/429 também carreguem os cabeçalhos CORS e o preflight (sem cookies)
 * // não seja barrado pela autenticação.
 * app.use(cors);
 * app.use(express.json());
 * // ... autenticação, resolução de tenant, rotas
 *
 * // Ao cadastrar/remover uma origem de um tenant: cors.invalidateCache(origin);
 *
 * Cookie de sessão para uso cross-site (obrigatório para o navegador enviá-lo):
 *   res.cookie('sid', token, { httpOnly: true, secure: true, sameSite: 'none', path: '/' });
 * No cliente: fetch(url, { credentials: 'include' }).
 * --------------------------------------------------------------------------- */