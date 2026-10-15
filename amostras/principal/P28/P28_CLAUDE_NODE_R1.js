'use strict';

/**
 * Middleware de verificação de assinatura para SaaS multilocatário.
 *
 * Requisitos: Node.js >= 18 (fetch e AbortController nativos).
 * Compatível com Express/Connect: (req, res, next).
 *
 * IMPORTANTE: deve ser registrado DEPOIS do middleware de autenticação,
 * que precisa preencher req.auth.tenantId a partir de um token validado.
 * O tenantId NUNCA deve vir de header, query ou body controlados pelo cliente.
 */

const DEFAULTS = {
  baseUrl: process.env.BILLING_API_URL,        // ex.: https://billing.exemplo.com
  apiKey: process.env.BILLING_API_KEY,         // credencial servidor-a-servidor
  timeoutMs: 2000,                             // limite de espera pelo faturamento
  cacheTtlMs: 30_000,                          // 0 = consulta o faturamento em TODA requisição
  staleIfErrorMs: 5 * 60_000,                  // tolerância se o faturamento estiver fora do ar
  failOpen: false,                             // false = bloqueia (503) se não houver como verificar
  maxCacheEntries: 10_000,
  allowedStatuses: ['active', 'trialing'],     // status que liberam o acesso
  getTenantId: (req) => req.auth?.tenantId,    // fonte confiável do tenant
  logger: console,
};

function createSubscriptionGuard(options = {}) {
  const cfg = { ...DEFAULTS, ...options };

  if (!cfg.baseUrl || !cfg.apiKey) {
    throw new Error('subscriptionGuard: baseUrl e apiKey do faturamento são obrigatórios.');
  }

  const allowed = new Set(cfg.allowedStatuses);
  const cache = new Map();     // tenantId -> { status, fetchedAt }
  const inflight = new Map();  // tenantId -> Promise (evita N chamadas simultâneas para o mesmo tenant)

  async function fetchSubscriptionStatus(tenantId) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);

    try {
      const url = `${cfg.baseUrl}/v1/subscriptions/${encodeURIComponent(tenantId)}`;
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${cfg.apiKey}`,
          Accept: 'application/json',
        },
        signal: controller.signal,
      });

      // Assinatura inexistente: resposta definitiva, não é falha do serviço.
      if (response.status === 404) return 'none';

      if (!response.ok) {
        throw new Error(`Faturamento respondeu HTTP ${response.status}`);
      }

      const body = await response.json();
      if (typeof body?.status !== 'string') {
        throw new Error('Resposta do faturamento em formato inesperado');
      }
      return body.status.toLowerCase();
    } finally {
      clearTimeout(timer);
    }
  }

  function getStatus(tenantId) {
    // Single-flight: reaproveita consulta já em andamento para o mesmo tenant.
    if (inflight.has(tenantId)) return inflight.get(tenantId);

    const promise = fetchSubscriptionStatus(tenantId)
      .then((status) => {
        if (cache.size >= cfg.maxCacheEntries) {
          cache.delete(cache.keys().next().value); // descarta a entrada mais antiga
        }
        cache.set(tenantId, { status, fetchedAt: Date.now() });
        return status;
      })
      .finally(() => inflight.delete(tenantId));

    inflight.set(tenantId, promise);
    return promise;
  }

  async function resolveStatus(tenantId) {
    const now = Date.now();
    const cached = cache.get(tenantId);

    if (cfg.cacheTtlMs > 0 && cached && now - cached.fetchedAt < cfg.cacheTtlMs) {
      return { status: cached.status };
    }

    try {
      return { status: await getStatus(tenantId) };
    } catch (err) {
      cfg.logger.error('[subscriptionGuard] falha ao consultar faturamento', {
        tenantId,
        error: err.message,
      });

      // Faturamento indisponível: usa o último valor conhecido por tempo limitado.
      if (cached && now - cached.fetchedAt < cfg.staleIfErrorMs) {
        return { status: cached.status, stale: true };
      }
      return { status: null, unavailable: true };
    }
  }

  return async function subscriptionGuard(req, res, next) {
    try {
      const tenantId = cfg.getTenantId(req);

      // Sem tenant autenticado, a requisição não deveria ter chegado aqui.
      if (!tenantId) {
        return res.status(401).json({ error: 'unauthenticated' });
      }

      const result = await resolveStatus(String(tenantId));

      if (result.unavailable) {
        if (cfg.failOpen) {
          cfg.logger.warn('[subscriptionGuard] failOpen: acesso liberado sem verificação', { tenantId });
          return next();
        }
        res.set('Retry-After', '5');
        return res.status(503).json({
          error: 'billing_unavailable',
          message: 'Não foi possível verificar a assinatura no momento. Tente novamente.',
        });
      }

      if (!allowed.has(result.status)) {
        // 402 Payment Required: assinatura inativa, vencida ou inexistente.
        return res.status(402).json({
          error: 'subscription_inactive',
          message: 'A assinatura da empresa não está ativa.',
        });
      }

      // Disponibiliza o resultado para as camadas seguintes (ex.: limites do plano).
      req.subscription = { status: result.status, stale: Boolean(result.stale) };
      return next();
    } catch (err) {
      cfg.logger.error('[subscriptionGuard] erro inesperado', { error: err.message });
      return res.status(500).json({ error: 'internal_error' });
    }
  };
}

module.exports = { createSubscriptionGuard };

/* ------------------------------------------------------------------ *
 * Exemplo de uso (Express)
 * ------------------------------------------------------------------ *
 *
 * const express = require('express');
 * const { authenticate } = require('./auth');   // valida o token e define req.auth.tenantId
 * const { createSubscriptionGuard } = require('./subscriptionGuard');
 *
 * const app = express();
 *
 * app.get('/health', (req, res) => res.send('ok'));   // rotas públicas ficam antes
 *
 * app.use(authenticate);                               // 1º: autentica
 * app.use(createSubscriptionGuard());                  // 2º: verifica a assinatura
 *
 * app.use('/api', apiRoutes);
 * ------------------------------------------------------------------ */