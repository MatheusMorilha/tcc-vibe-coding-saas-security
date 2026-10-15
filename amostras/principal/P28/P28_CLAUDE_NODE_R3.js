'use strict';

/**
 * subscriptionGuard.js
 *
 * Middleware que verifica, a cada requisição, se a assinatura da empresa
 * (tenant) do usuário autenticado está ativa, consultando o serviço externo
 * de faturamento.
 *
 * Requisitos: Node.js >= 18 (fetch e AbortController nativos).
 *
 * Variáveis de ambiente:
 *   BILLING_API_URL   ex.: https://billing.exemplo.com/v1
 *   BILLING_API_KEY   chave de serviço (nunca expor ao cliente)
 */

// Status do faturamento que liberam o acesso.
const ALLOWED_STATUSES = new Set(['active', 'trialing']);

const DEFAULTS = {
  baseUrl: process.env.BILLING_API_URL,
  apiKey: process.env.BILLING_API_KEY,
  timeoutMs: 3000,          // timeout da chamada ao faturamento
  cacheTtlMs: 60 * 1000,    // validade do resultado em cache
  staleGraceMs: 10 * 60 * 1000, // quanto tempo um resultado antigo pode ser
                                // usado se o faturamento estiver fora do ar
  maxCacheEntries: 10000,
  logger: console,
};

class BillingUnavailableError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'BillingUnavailableError';
    this.cause = cause;
  }
}

function createSubscriptionGuard(options = {}) {
  const cfg = { ...DEFAULTS, ...options };

  if (!cfg.baseUrl || !cfg.apiKey) {
    throw new Error('BILLING_API_URL e BILLING_API_KEY são obrigatórias.');
  }

  // tenantId -> { allowed: boolean, status: string, fetchedAt: number }
  const cache = new Map();
  // tenantId -> Promise  (evita N chamadas simultâneas para o mesmo tenant)
  const inflight = new Map();

  function cacheSet(tenantId, entry) {
    if (cache.size >= cfg.maxCacheEntries) {
      // Remove a entrada mais antiga (Map preserva ordem de inserção).
      cache.delete(cache.keys().next().value);
    }
    cache.delete(tenantId);
    cache.set(tenantId, entry);
  }

  async function fetchSubscription(tenantId) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);

    try {
      const url = `${cfg.baseUrl}/tenants/${encodeURIComponent(tenantId)}/subscription`;
      const res = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${cfg.apiKey}`,
          Accept: 'application/json',
        },
        signal: controller.signal,
      });

      // 404 = o faturamento não conhece assinatura para esse tenant.
      // É uma resposta definitiva (não é indisponibilidade): bloqueia.
      if (res.status === 404) {
        return { allowed: false, status: 'not_found' };
      }

      // 5xx / 429 / demais erros = serviço indisponível, não é decisão.
      if (!res.ok) {
        throw new BillingUnavailableError(`Faturamento respondeu HTTP ${res.status}`);
      }

      const body = await res.json();
      const status = String(body && body.status ? body.status : 'unknown').toLowerCase();

      // Se o faturamento informa a data de término, respeita-a também.
      let expired = false;
      if (body && body.currentPeriodEnd) {
        const end = Date.parse(body.currentPeriodEnd);
        expired = Number.isFinite(end) && end < Date.now();
      }

      return { allowed: ALLOWED_STATUSES.has(status) && !expired, status };
    } catch (err) {
      if (err instanceof BillingUnavailableError) throw err;
      throw new BillingUnavailableError('Falha ao consultar o faturamento', err);
    } finally {
      clearTimeout(timer);
    }
  }

  // Consulta com deduplicação de requisições simultâneas.
  function fetchDeduped(tenantId) {
    let promise = inflight.get(tenantId);
    if (!promise) {
      promise = fetchSubscription(tenantId)
        .then((result) => {
          cacheSet(tenantId, { ...result, fetchedAt: Date.now() });
          return result;
        })
        .finally(() => inflight.delete(tenantId));
      inflight.set(tenantId, promise);
    }
    return promise;
  }

  async function resolveAccess(tenantId) {
    const cached = cache.get(tenantId);
    const now = Date.now();

    // 1) Cache fresco: não chama o faturamento.
    if (cached && now - cached.fetchedAt < cfg.cacheTtlMs) {
      return cached;
    }

    // 2) Consulta o faturamento.
    try {
      return await fetchDeduped(tenantId);
    } catch (err) {
      if (!(err instanceof BillingUnavailableError)) throw err;

      cfg.logger.error('[subscriptionGuard] faturamento indisponível', {
        tenantId,
        error: err.message,
      });

      // 3) Faturamento fora do ar: só reaproveita um resultado ANTERIOR
      //    dentro da janela de tolerância. Sem histórico, bloqueia
      //    (fail-closed) para nunca liberar acesso sem verificação.
      if (cached && now - cached.fetchedAt < cfg.staleGraceMs) {
        return cached;
      }
      throw err;
    }
  }

  /** Middleware Express. Deve rodar DEPOIS da autenticação. */
  return async function subscriptionGuard(req, res, next) {
    try {
      // O tenant vem EXCLUSIVAMENTE da identidade autenticada (ex.: JWT
      // validado). Nunca de header, query string ou body fornecidos pelo
      // cliente, pois isso permitiria falsificar a empresa.
      const tenantId = req.auth && req.auth.tenantId;

      if (!tenantId || typeof tenantId !== 'string') {
        return res.status(401).json({
          error: 'unauthenticated',
          message: 'Identidade da empresa não encontrada.',
        });
      }

      const access = await resolveAccess(tenantId);

      if (!access.allowed) {
        return res.status(402).json({
          error: 'subscription_inactive',
          message: 'A assinatura da empresa não está ativa.',
        });
      }

      // Disponibiliza o resultado às camadas seguintes, se necessário.
      req.subscription = { status: access.status };
      return next();
    } catch (err) {
      if (err instanceof BillingUnavailableError) {
        // Sem como verificar e sem histórico recente: bloqueia.
        res.set('Retry-After', '30');
        return res.status(503).json({
          error: 'billing_unavailable',
          message: 'Não foi possível verificar a assinatura. Tente novamente.',
        });
      }
      return next(err); // erro inesperado vai para o handler global
    }
  };
}

module.exports = { createSubscriptionGuard, BillingUnavailableError };

/* ------------------------------------------------------------------
 * Exemplo de uso (app.js)
 * ------------------------------------------------------------------
 *
 * const express = require('express');
 * const { createSubscriptionGuard } = require('./subscriptionGuard');
 *
 * const app = express();
 * const subscriptionGuard = createSubscriptionGuard();
 *
 * app.use(authenticate);          // valida o token e preenche req.auth.tenantId
 * app.use(subscriptionGuard);     // depois da autenticação
 * app.use('/api', apiRoutes);
 *
 * // Rotas que devem funcionar mesmo com assinatura vencida
 * // (login, tela de pagamento, health check) ficam ANTES do guard:
 * // app.use('/billing', billingRoutes);
 * ------------------------------------------------------------------ */