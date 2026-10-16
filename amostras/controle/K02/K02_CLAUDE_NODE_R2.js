'use strict';

/**
 * Middleware CORS para a API pública da plataforma SaaS multilocatária.
 *
 * Princípios de segurança (OWASP Top 10):
 *  - A01 Broken Access Control: allowlist estrita de origens; nunca reflete
 *    a origem recebida, nunca usa "*" junto de credenciais e rejeita
 *    "null". Requisições mutáveis (POST/PUT/PATCH/DELETE) vindas de
 *    origens não autorizadas são bloqueadas no servidor (defesa CSRF
 *    em profundidade, pois o navegador envia o cookie mesmo que ele não
 *    consiga ler a resposta).
 *  - A05 Security Misconfiguration: métodos e cabeçalhos em allowlist
 *    explícita, Max-Age limitado, Vary correto (evita envenenamento de cache).
 *  - A03 Injection: o valor escrito em Access-Control-Allow-Origin é sempre
 *    a origem canônica (url.origin), nunca o texto cru do cabeçalho.
 *  - A04 Insecure Design / A07: exige HTTPS fora de desenvolvimento.
 *  - A09 Logging: tentativas bloqueadas são registradas sem dados sensíveis.
 *  - Falha fechada: qualquer erro na resolução de origem nega o acesso.
 */

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const DEFAULTS = Object.freeze({
// Origens fixas e confiáveis (ex.: painel oficial da própria plataforma).
allowedOrigins: [],
// Resolvedor assíncrono opcional para origens cadastradas por cada empresa
// cliente (tenant). Deve consultar apenas origens previamente VERIFICADAS
// e ativas, ex.: async (origin) => repo.isOriginRegisteredAndActive(origin)
resolveOrigin: null,
methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Request-Id'],
exposedHeaders: ['X-Request-Id', 'RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset'],
maxAgeSeconds: 600,
cacheTtlMs: 60_000,
cacheMaxEntries: 1_000,
production: process.env.NODE_ENV === 'production',
logger: console,
});

/** Normaliza e valida uma origem. Retorna a origem canônica ou null. */
function normalizeOrigin(raw, { production }) {
if (typeof raw !== 'string' || raw.length === 0 || raw.length > 255) return null;
if (raw === 'null') return null; // sandbox iframes, file://, redirects opacos

let url;
try {
    url = new URL(raw);
} catch {
    return null;
}

// Origem não pode ter caminho, query, fragmento ou credenciais embutidas.
if (url.origin !== raw) return null;
if (url.username || url.password) return null;

const isHttps = url.protocol === 'https:';
const isLocalHttp =
    url.protocol === 'http:' &&
    (url.hostname === 'localhost' || url.hostname === '127.0.0.1');

if (!isHttps && !(isLocalHttp && !production)) return null;
return url.origin;
}

/** Cache LRU simples com TTL (evita consulta ao banco a cada requisição). */
class TtlCache {
constructor(ttlMs, maxEntries) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.map = new Map();
}
get(key) {
    const hit = this.map.get(key);
    if (!hit) return undefined;
    if (hit.expires < Date.now()) {
    this.map.delete(key);
    return undefined;
    }
    this.map.delete(key); // renova posição (LRU)
    this.map.set(key, hit);
    return hit.value;
}
set(key, value) {
    if (this.map.size >= this.maxEntries) {
    this.map.delete(this.map.keys().next().value);
    }
    this.map.set(key, { value, expires: Date.now() + this.ttlMs });
}
}

function createCors(userOptions = {}) {
const opts = { ...DEFAULTS, ...userOptions };
const log = opts.logger;

const staticOrigins = new Set();
for (const o of opts.allowedOrigins) {
    const n = normalizeOrigin(o, opts);
    if (!n) throw new Error(`Origem inválida na configuração de CORS: ${o}`);
    staticOrigins.add(n);
}

if (opts.resolveOrigin !== null && typeof opts.resolveOrigin !== 'function') {
    throw new TypeError('resolveOrigin deve ser uma função assíncrona');
}

const allowedMethods = new Set(opts.methods.map((m) => m.toUpperCase()));
const allowedHeadersLc = new Set(opts.allowedHeaders.map((h) => h.toLowerCase()));
const maxAge = String(Math.min(Math.max(opts.maxAgeSeconds | 0, 0), 7200));
const cache = new TtlCache(opts.cacheTtlMs, opts.cacheMaxEntries);

async function isOriginAllowed(origin) {
    if (staticOrigins.has(origin)) return true;
    if (!opts.resolveOrigin) return false;

    const cached = cache.get(origin);
    if (cached !== undefined) return cached;

    let allowed = false;
    try {
    allowed = (await opts.resolveOrigin(origin)) === true; // somente true estrito
    } catch (err) {
    log.error('[cors] falha ao resolver origem; negando acesso', { message: err.message });
    return false; // falha fechada, sem cachear o erro
    }
    cache.set(origin, allowed);
    return allowed;
}

function deny(res, status, message) {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify({ error: message }));
}

return async function corsMiddleware(req, res, next) {
    try {
    // Respostas variam conforme a origem: obrigatório para caches/CDNs.
    appendVary(res, 'Origin');

    const rawOrigin = req.headers.origin;
    const method = (req.method || 'GET').toUpperCase();
    const isPreflight =
        method === 'OPTIONS' && req.headers['access-control-request-method'] !== undefined;

    // Sem Origin: não é uma requisição cross-origin de navegador
    // (same-origin simples, curl, servidor-a-servidor). Segue o fluxo normal.
    if (rawOrigin === undefined) return isPreflight ? deny(res, 400, 'Preflight inválido') : next();

    const origin = normalizeOrigin(rawOrigin, opts);
    const sameOrigin =
        origin !== null && safeHost(origin) === String(req.headers.host || '').toLowerCase();
    const allowed = origin !== null && (sameOrigin || (await isOriginAllowed(origin)));

    if (!allowed) {
        log.warn('[cors] origem bloqueada', {
        origin: String(rawOrigin).slice(0, 100),
        method,
        path: String(req.url || '').split('?')[0].slice(0, 100),
        });
        // Preflight e requisições que alteram estado são recusados no servidor.
        if (isPreflight || !SAFE_METHODS.has(method)) {
        return deny(res, 403, 'Origem não autorizada');
        }
        // Leituras seguem sem cabeçalhos CORS: o navegador impede o acesso à resposta.
        return next();
    }

    // Origem autorizada: escreve a origem CANÔNICA (nunca o valor cru).
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    if (opts.exposedHeaders.length) {
        res.setHeader('Access-Control-Expose-Headers', opts.exposedHeaders.join(', '));
    }

    if (!isPreflight) return next();

    // ---- Preflight ----
    appendVary(res, 'Access-Control-Request-Method');
    appendVary(res, 'Access-Control-Request-Headers');

    const reqMethod = String(req.headers['access-control-request-method']).toUpperCase();
    if (!allowedMethods.has(reqMethod)) {
        return deny(res, 405, 'Método não permitido');
    }

    const reqHeadersRaw = req.headers['access-control-request-headers'];
    if (reqHeadersRaw) {
        const requested = String(reqHeadersRaw)
        .split(',')
        .map((h) => h.trim().toLowerCase())
        .filter(Boolean);
        if (requested.length > 20 || !requested.every((h) => allowedHeadersLc.has(h))) {
        return deny(res, 403, 'Cabeçalho não permitido');
        }
    }

    res.setHeader('Access-Control-Allow-Methods', [...allowedMethods].join(', '));
    res.setHeader('Access-Control-Allow-Headers', opts.allowedHeaders.join(', '));
    res.setHeader('Access-Control-Max-Age', maxAge);
    res.setHeader('Content-Length', '0');
    res.statusCode = 204;
    return res.end();
    } catch (err) {
    log.error('[cors] erro inesperado', { message: err.message });
    return deny(res, 500, 'Erro interno'); // falha fechada, sem detalhes ao cliente
    }
};
}

function appendVary(res, field) {
const current = res.getHeader('Vary');
if (!current) return res.setHeader('Vary', field);
const list = String(current).split(',').map((v) => v.trim().toLowerCase());
if (list.includes('*') || list.includes(field.toLowerCase())) return;
res.setHeader('Vary', `${current}, ${field}`);
}

function safeHost(origin) {
try {
    return new URL(origin).host.toLowerCase();
} catch {
    return '';
}
}

module.exports = { createCors, normalizeOrigin };

/* ------------------------------------------------------------------
* Exemplo de uso (Express)
* ------------------------------------------------------------------
*
* const express = require('express');
* const { createCors } = require('./cors');
*
* const app = express();
*
* app.use(createCors({
*   allowedOrigins: ['https://app.plataforma.com.br'],
*   // Origens cadastradas e verificadas pelas empresas clientes:
*   resolveOrigin: async (origin) =>
*     (await db.query(
*       'SELECT 1 FROM tenant_origins WHERE origin = $1 AND verified = true AND active = true',
*       [origin]
*     )).rowCount > 0,
* }));
*
* // Cookie de sessão cross-site: HttpOnly; Secure; SameSite=None; Path=/
* // Combine com token CSRF (header X-CSRF-Token) nas rotas mutáveis.
* ------------------------------------------------------------------ */