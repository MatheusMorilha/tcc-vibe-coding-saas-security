'use strict';

/**
 * subscription-guard.js
 *
 * Middleware que verifica, no serviço externo de faturamento, se a assinatura
 * da empresa (tenant) está ativa, liberando ou bloqueando a requisição.
 *
 * PRÉ-REQUISITOS
 *  - Node.js >= 18 (fetch / AbortController nativos).
 *  - Um middleware de autenticação anterior a este deve validar o token
 *    (assinatura, expiração, issuer, audience) e popular:
 *        req.auth = { userId: '<uuid>', tenantId: '<uuid>' }
 *    O tenantId SEMPRE vem da identidade autenticada, nunca de header,
 *    query string, body ou path controlados pelo cliente.
 *
 * VARIÁVEIS DE AMBIENTE
 *  - BILLING_API_URL : URL base HTTPS do serviço de faturamento
 *  - BILLING_API_KEY : credencial de serviço (use um secret manager em produção)
 *
 * CONTRATO ASSUMIDO DO SERVIÇO DE FATURAMENTO
 *  GET {BILLING_API_URL}/subscriptions/{tenantId}
 *   200 -> { "status": "active|trialing|past_due|canceled|unpaid|expired|paused",
 *            "currentPeriodEnd": "2026-12-31T23:59:59Z" (opcional) }
 *   404 -> empresa sem assinatura
 */

const { randomUUID } = require('node:crypto');

/* ------------------------------------------------------------------ */
/* Configuração (A05 - Security Misconfiguration)                      */
/* ------------------------------------------------------------------ */

function requireEnv(name) {
  const value = process.env[name];
  if (!value || !value.trim()) {
    // Falha no boot: "fail fast" em vez de subir inseguro.
    throw new Error(`Variável de ambiente obrigatória ausente: ${name}`);
  }
  return value.trim();
}

function buildBaseUrl(raw) {
  const url = new URL(raw);
  const isProd = process.env.NODE_ENV === 'production';
  // A02 - Cryptographic Failures: exige TLS (credencial trafega no header).
  if (url.protocol !== 'https:' && (isProd || url.protocol !== 'http:')) {
    throw new Error('BILLING_API_URL deve usar HTTPS');
  }
  if (url.username || url.password) {
    throw new Error('BILLING_API_URL não deve conter credenciais embutidas');
  }
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  return url;
}

const CONFIG = Object.freeze({
  baseUrl: buildBaseUrl(requireEnv('BILLING_API_URL')),
  apiKey: requireEnv('BILLING_API_KEY'),
  timeoutMs: 3000,                 // evita requisições presas (A04/DoS)
  maxResponseBytes: 16 * 1024,     // limita o corpo aceito do serviço externo
  ttlActiveMs: 60_000,             // cache de assinatura ativa
  ttlInactiveMs: 15_000,           // cache menor para bloqueio (reativação rápida)
  staleGraceMs: 5 * 60_000,        // tolerância máxima se o faturamento cair
  maxCacheEntries: 10_000,         // cache limitado (evita esgotar memória)
  breakerFailureThreshold: 5,
  breakerOpenMs: 10_000,
  // Status que liberam acesso. past_due fica de fora por padrão (decisão de negócio).
  allowedStatuses: new Set(['active', 'trialing']),
  knownStatuses: new Set([
    'active', 'trialing', 'past_due', 'canceled', 'unpaid', 'expired', 'paused',
  ]),
});

/* ------------------------------------------------------------------ */
/* Utilitários                                                         */
/* ------------------------------------------------------------------ */

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const isUuid = (v) => typeof v === 'string' && UUID_RE.test(v);

class BillingUnavailableError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'BillingUnavailableError';
  }
}

/** Lê o corpo da resposta com limite rígido de bytes. */
async function readLimitedText(res, maxBytes) {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new BillingUnavailableError('resposta excede o limite');
  }
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new BillingUnavailableError('resposta excede o limite');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/* ------------------------------------------------------------------ */
/* Cache LRU simples + coalescência de requisições                     */
/* ------------------------------------------------------------------ */

const cache = new Map();     // tenantId -> { active, status, fetchedAt, expiresAt }
const inflight = new Map();  // tenantId -> Promise (evita "thundering herd")

function cacheGet(tenantId) {
  const entry = cache.get(tenantId);
  if (entry) {                       // renova posição (LRU)
    cache.delete(tenantId);
    cache.set(tenantId, entry);
  }
  return entry;
}

function cacheSet(tenantId, entry) {
  cache.delete(tenantId);
  cache.set(tenantId, entry);
  while (cache.size > CONFIG.maxCacheEntries) {
    cache.delete(cache.keys().next().value); // remove o mais antigo
  }
}

/** Para uso em webhook de faturamento (cuja assinatura deve ser validada). */
function invalidateSubscriptionCache(tenantId) {
  if (isUuid(tenantId)) cache.delete(tenantId);
}

/* ------------------------------------------------------------------ */
/* Circuit breaker mínimo                                              */
/* ------------------------------------------------------------------ */

const breaker = { failures: 0, openUntil: 0 };

const breakerIsOpen = () => Date.now() < breaker.openUntil;
const breakerSuccess = () => { breaker.failures = 0; };
function breakerFailure() {
  breaker.failures += 1;
  if (breaker.failures >= CONFIG.breakerFailureThreshold) {
    breaker.openUntil = Date.now() + CONFIG.breakerOpenMs;
    breaker.failures = 0;
  }
}

/* ------------------------------------------------------------------ */
/* Consulta ao serviço externo                                         */
/* ------------------------------------------------------------------ */

function evaluate(body) {
  // A08 - Data Integrity: valida o contrato antes de confiar na resposta.
  if (
    !body || typeof body !== 'object' ||
    typeof body.status !== 'string' ||
    !CONFIG.knownStatuses.has(body.status)
  ) {
    throw new BillingUnavailableError('payload inválido do faturamento');
  }

  let active = CONFIG.allowedStatuses.has(body.status);

  if (active && body.currentPeriodEnd !== undefined) {
    const end = Date.parse(body.currentPeriodEnd);
    if (Number.isNaN(end)) {
      throw new BillingUnavailableError('currentPeriodEnd inválido');
    }
    if (end < Date.now()) active = false; // período vencido
  }
  return { active, status: body.status };
}

async function fetchFromBilling(tenantId, requestId) {
  if (breakerIsOpen()) throw new BillingUnavailableError('circuit breaker aberto');

  // A03/A10 - Injection/SSRF: host fixo vindo da configuração; tenantId já
  // validado como UUID e ainda codificado no path.
  const url = new URL(`subscriptions/${encodeURIComponent(tenantId)}`, CONFIG.baseUrl);
  if (url.origin !== CONFIG.baseUrl.origin) {
    throw new BillingUnavailableError('origem inesperada');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CONFIG.timeoutMs);

  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${CONFIG.apiKey}`,
        Accept: 'application/json',
        'X-Request-Id': requestId,
      },
      redirect: 'error',            // A10 - não segue redirecionamentos
      signal: controller.signal,
    });

    if (res.status === 404) {
      breakerSuccess();
      await res.body?.cancel();
      return { active: false, status: 'none' };
    }
    if (!res.ok) {
      await res.body?.cancel();
      // 401/403 aqui indicam problema NOSSO de credencial; 5xx, do provedor.
      throw new BillingUnavailableError(`faturamento respondeu HTTP ${res.status}`);
    }

    const ct = res.headers.get('content-type') || '';
    if (!ct.toLowerCase().includes('application/json')) {
      throw new BillingUnavailableError('content-type inesperado');
    }

    const text = await readLimitedText(res, CONFIG.maxResponseBytes);
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new BillingUnavailableError('JSON inválido');
    }

    const result = evaluate(parsed);
    breakerSuccess();
    return result;
  } catch (err) {
    breakerFailure();
    if (err instanceof BillingUnavailableError) throw err;
    throw new BillingUnavailableError(
      err && err.name === 'AbortError' ? 'timeout' : 'falha de rede',
    );
  } finally {
    clearTimeout(timer);
  }
}

/** Resolve o estado da assinatura usando cache + coalescência. */
async function resolveSubscription(tenantId, requestId) {
  const cached = cacheGet(tenantId);
  if (cached && cached.expiresAt > Date.now()) {
    return { ...cached, stale: false };
  }

  let promise = inflight.get(tenantId);
  if (!promise) {
    promise = fetchFromBilling(tenantId, requestId)
      .then((r) => {
        const now = Date.now();
        const ttl = r.active ? CONFIG.ttlActiveMs : CONFIG.ttlInactiveMs;
        const entry = { ...r, fetchedAt: now, expiresAt: now + ttl };
        cacheSet(tenantId, entry);
        return entry;
      })
      .finally(() => inflight.delete(tenantId));
    inflight.set(tenantId, promise);
  }

  try {
    return { ...(await promise), stale: false };
  } catch (err) {
    // Faturamento indisponível: tolera SOMENTE um "ativo" recente (stale-if-error).
    // Nunca libera tenant que estava bloqueado ou sem histórico (fail-closed).
    if (
      err instanceof BillingUnavailableError &&
      cached && cached.active &&
      Date.now() - cached.fetchedAt <= CONFIG.staleGraceMs
    ) {
      return { ...cached, stale: true };
    }
    throw err;
  }
}

/* ------------------------------------------------------------------ */
/* Middleware                                                          */
/* ------------------------------------------------------------------ */

/**
 * @param {object}   [options]
 * @param {string[]} [options.exemptRoutes] Rotas EXATAS isentas, formato "METHOD /caminho"
 *                   (ex.: ['GET /health', 'POST /billing/webhook']). Use com parcimônia.
 * @param {object}   [options.logger]       Objeto com info/warn/error (ex.: pino).
 */
function requireActiveSubscription(options = {}) {
  const exempt = new Set(options.exemptRoutes || []);
  const logger = options.logger || console;

  return async function subscriptionGuard(req, res, next) {
    const requestId = req.id || randomUUID();

    try {
      // Comparação exata (sem prefixo/regex) para não abrir exceções acidentais.
      if (exempt.has(`${req.method} ${req.path}`)) return next();

      // A07 - Authentication Failures: exige identidade já autenticada.
      if (!req.auth || typeof req.auth !== 'object') {
        return deny(res, 401, 'UNAUTHENTICATED', 'Autenticação necessária.');
      }

      // A01 - Broken Access Control: tenant vem do token validado e é checado.
      const { tenantId } = req.auth;
      if (!isUuid(tenantId)) {
        logger.warn({ requestId, event: 'invalid_tenant_claim' }, 'tenant inválido no token');
        return deny(res, 403, 'FORBIDDEN', 'Acesso negado.');
      }

      const sub = await resolveSubscription(tenantId, requestId);

      if (!sub.active) {
        // A09 - Logging: registra decisão sem dados sensíveis.
        logger.info(
          { requestId, tenantId, userId: req.auth.userId, status: sub.status, event: 'subscription_blocked' },
          'acesso bloqueado: assinatura inativa',
        );
        return deny(res, 402, 'SUBSCRIPTION_INACTIVE',
          'A assinatura da empresa não está ativa.');
      }

      if (sub.stale) {
        logger.warn({ requestId, tenantId, event: 'billing_stale_allow' },
          'faturamento indisponível: usando último estado ativo conhecido');
      }

      // Disponibiliza o estado para handlers posteriores (somente leitura).
      req.subscription = Object.freeze({ status: sub.status });
      return next();
    } catch (err) {
      if (err instanceof BillingUnavailableError) {
        // A10 - tratamento de condições excepcionais: FAIL-CLOSED.
        logger.error({ requestId, event: 'billing_unavailable', reason: err.message },
          'não foi possível verificar a assinatura');
        res.set('Retry-After', '10');
        return deny(res, 503, 'BILLING_UNAVAILABLE',
          'Não foi possível validar a assinatura no momento. Tente novamente.');
      }
      logger.error({ requestId, event: 'subscription_guard_error' }, 'erro inesperado no middleware');
      return deny(res, 500, 'INTERNAL_ERROR', 'Erro interno.');
    }
  };
}

/** Resposta de erro padronizada e genérica (sem stack trace nem detalhes internos). */
function deny(res, status, code, message) {
  res.set('Cache-Control', 'no-store');
  return res.status(status).json({ error: { code, message } });
}

module.exports = { requireActiveSubscription, invalidateSubscriptionCache };

/* ------------------------------------------------------------------ */
/* EXEMPLO DE USO                                                      */
/* ------------------------------------------------------------------ */
/*
const express = require('express');
const helmet = require('helmet');
const { authenticate } = require('./auth');       // valida JWT e popula req.auth
const { requireActiveSubscription } = require('./subscription-guard');

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '100kb' }));

app.get('/health', (req, res) => res.json({ ok: true }));

// A ordem importa: autenticação -> assinatura -> rotas de negócio
app.use(authenticate);
app.use(requireActiveSubscription({
  // Mantenha rotas de pagamento acessíveis para que o cliente possa regularizar.
  exemptRoutes: ['GET /billing/status', 'POST /billing/checkout'],
}));

app.use('/api', require('./routes'));
*/