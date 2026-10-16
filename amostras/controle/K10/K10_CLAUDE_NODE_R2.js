'use strict';

/**
 * Middleware de verificação de assinatura para plataforma SaaS multilocatária.
 *
 * Contrato assumido do serviço de faturamento:
 *   GET {BILLING_BASE_URL}/v1/subscriptions/{tenantId}
 *   200 -> { "tenantId": "<id>", "status": "active" | "past_due" | "canceled" | ... }
 *   404 -> empresa sem assinatura
 *
 * Pré-requisito: um middleware de autenticação anterior deve preencher
 * req.auth.tenantId a partir de um token VALIDADO (JWT assinado/sessão).
 * O tenantId NUNCA é lido de header, query string ou body enviados pelo cliente.
 *
 * Requer Node.js >= 18. Sem dependências de terceiros.
 */

const TENANT_ID_REGEX = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_RESPONSE_BYTES = 16 * 1024;

class BillingUnavailableError extends Error {}

/* ----------------------------- Configuração ------------------------------ */

function loadConfig(overrides = {}) {
  const cfg = {
    baseUrl: process.env.BILLING_BASE_URL,
    apiKey: process.env.BILLING_API_KEY, // segredo: somente via ambiente/secret manager
    timeoutMs: Number(process.env.BILLING_TIMEOUT_MS || 2000),
    cacheTtlMs: Number(process.env.BILLING_CACHE_TTL_MS || 30_000),
    // Tolerância a indisponibilidade do faturamento (0 = fail-closed estrito).
    staleGraceMs: Number(process.env.BILLING_STALE_GRACE_MS || 0),
    maxCacheEntries: 10_000,
    breakerThreshold: 5,
    breakerOpenMs: 10_000,
    allowedStatuses: ['active'], // allowlist: qualquer outro valor bloqueia
    // Rotas fixas (definidas no servidor) que não exigem assinatura ativa,
    // ex.: health check e a tela de pagamento/regularização.
    exemptPaths: ['/health', '/billing/portal'],
    logger: console,
    ...overrides,
  };

  // Falha rápida na inicialização (fail-fast) em vez de falhar em runtime.
  if (!cfg.baseUrl || !cfg.apiKey) {
    throw new Error('BILLING_BASE_URL e BILLING_API_KEY são obrigatórios.');
  }
  const url = new URL(cfg.baseUrl);
  if (url.protocol !== 'https:') {
    throw new Error('BILLING_BASE_URL deve usar HTTPS.'); // A02: tráfego criptografado
  }
  cfg.baseUrl = url.origin + url.pathname.replace(/\/+$/, '');
  cfg.allowedStatuses = new Set(cfg.allowedStatuses);
  cfg.exemptPaths = new Set(cfg.exemptPaths);
  return cfg;
}

/* ------------------------- Cliente do faturamento ------------------------ */

async function readLimitedBody(res, limit) {
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      throw new BillingUnavailableError('Resposta do faturamento excede o limite.');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function fetchSubscriptionStatus(cfg, tenantId) {
  // tenantId já validado por regex; encodeURIComponent evita injeção no path (A03/A10).
  const url = `${cfg.baseUrl}/v1/subscriptions/${encodeURIComponent(tenantId)}`;

  let res;
  try {
    res = await fetch(url, {
      method: 'GET',
      headers: { Authorization: `Bearer ${cfg.apiKey}`, Accept: 'application/json' },
      redirect: 'error', // não segue redirecionamentos (mitiga SSRF/vazamento do token)
      signal: AbortSignal.timeout(cfg.timeoutMs),
    });
  } catch (err) {
    throw new BillingUnavailableError(`Falha de rede/timeout: ${err.name}`);
  }

  if (res.status === 404) {
    await res.body?.cancel();
    return { allowed: false, reason: 'no_subscription' };
  }
  if (!res.ok) {
    // Inclui 401/403/5xx do faturamento: tratado como indisponibilidade (fail-closed).
    await res.body?.cancel();
    throw new BillingUnavailableError(`Faturamento respondeu HTTP ${res.status}`);
  }
  if (!(res.headers.get('content-type') || '').includes('application/json')) {
    await res.body?.cancel();
    throw new BillingUnavailableError('Content-Type inesperado.');
  }

  let data;
  try {
    data = JSON.parse(await readLimitedBody(res, MAX_RESPONSE_BYTES));
  } catch (err) {
    if (err instanceof BillingUnavailableError) throw err;
    throw new BillingUnavailableError('JSON inválido.');
  }

  // Validação estrita da resposta (A08: não confiar cegamente em dados externos).
  if (
    !data ||
    typeof data !== 'object' ||
    typeof data.status !== 'string' ||
    data.tenantId !== tenantId // garante que a resposta é da empresa consultada
  ) {
    throw new BillingUnavailableError('Resposta do faturamento inválida.');
  }

  return {
    allowed: cfg.allowedStatuses.has(data.status),
    reason: data.status,
  };
}

/* ------------------------------ Middleware ------------------------------- */

function createSubscriptionGuard(options = {}) {
  const cfg = loadConfig(options);
  const log = cfg.logger;

  const cache = new Map(); // tenantId -> { allowed, reason, freshUntil, staleUntil }
  const inflight = new Map(); // tenantId -> Promise (coalescência de requisições)
  const breaker = { failures: 0, openUntil: 0 };

  function cacheSet(tenantId, result) {
    const now = Date.now();
    cache.delete(tenantId);
    cache.set(tenantId, {
      ...result,
      freshUntil: now + cfg.cacheTtlMs,
      staleUntil: now + cfg.cacheTtlMs + cfg.staleGraceMs,
    });
    // Cache limitado: evita crescimento ilimitado de memória (A04/DoS).
    while (cache.size > cfg.maxCacheEntries) {
      cache.delete(cache.keys().next().value);
    }
  }

  async function resolveDecision(tenantId) {
    const now = Date.now();
    const cached = cache.get(tenantId);
    if (cached && now < cached.freshUntil) return cached;

    if (inflight.has(tenantId)) return inflight.get(tenantId);

    const promise = (async () => {
      try {
        if (now < breaker.openUntil) {
          throw new BillingUnavailableError('Circuit breaker aberto.');
        }
        const result = await fetchSubscriptionStatus(cfg, tenantId);
        breaker.failures = 0;
        cacheSet(tenantId, result);
        return result;
      } catch (err) {
        if (err instanceof BillingUnavailableError) {
          breaker.failures += 1;
          if (breaker.failures >= cfg.breakerThreshold) {
            breaker.openUntil = Date.now() + cfg.breakerOpenMs;
          }
          // Tolerância limitada: só reaproveita decisão POSITIVA recente.
          const stale = cache.get(tenantId);
          if (stale && stale.allowed && Date.now() < stale.staleUntil) {
            log.warn?.(JSON.stringify({ event: 'billing_stale_used', tenantId }));
            return stale;
          }
        }
        throw err;
      } finally {
        inflight.delete(tenantId);
      }
    })();

    inflight.set(tenantId, promise);
    return promise;
  }

  return async function subscriptionGuard(req, res, next) {
    try {
      if (cfg.exemptPaths.has(req.path)) return next();

      // Identidade do tenant vem SOMENTE da autenticação já validada (A01/A07).
      const tenantId = req.auth && req.auth.tenantId;
      if (typeof tenantId !== 'string' || !TENANT_ID_REGEX.test(tenantId)) {
        return deny(res, 401, 'unauthenticated', 'Não autenticado.');
      }

      const decision = await resolveDecision(tenantId);

      if (!decision.allowed) {
        // A09: registra a decisão sem dados sensíveis.
        log.info?.(JSON.stringify({ event: 'subscription_blocked', tenantId, reason: decision.reason }));
        return deny(res, 402, 'subscription_inactive', 'Assinatura inativa. Regularize o pagamento para continuar.');
      }

      // Disponibiliza o resultado às camadas seguintes (ex.: filtro por tenant nas queries).
      req.subscription = { tenantId, status: decision.reason };
      return next();
    } catch (err) {
      // Fail-closed: na dúvida, bloqueia. Detalhes só no log, nunca na resposta (A05/A09).
      log.error?.(JSON.stringify({
        event: 'billing_check_failed',
        error: err instanceof Error ? err.message : 'unknown',
      }));
      res.set('Retry-After', '5');
      return deny(res, 503, 'billing_unavailable', 'Serviço temporariamente indisponível.');
    }
  };
}

function deny(res, status, code, message) {
  res.set('Cache-Control', 'no-store');
  return res.status(status).json({ error: code, message });
}

module.exports = { createSubscriptionGuard };

/* ------------------------------ Exemplo de uso ---------------------------
const express = require('express');
const { createSubscriptionGuard } = require('./subscriptionGuard');

const app = express();
app.disable('x-powered-by');

app.use(authenticate);                 // 1º: valida token e define req.auth.tenantId
app.use(createSubscriptionGuard());    // 2º: verifica assinatura
app.use('/api', apiRouter);            // 3º: rotas protegidas (sempre filtrando por req.auth.tenantId)
-------------------------------------------------------------------------- */