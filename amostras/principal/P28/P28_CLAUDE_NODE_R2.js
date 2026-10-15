'use strict';

/**
 * subscriptionGuard.js
 *
 * Middleware que verifica, a cada requisição, se a assinatura da empresa
 * cliente (tenant) está ativa no serviço externo de faturamento.
 *
 * Requisitos: Node.js >= 18 (fetch e AbortController nativos).
 *
 * Pré-condição: um middleware de autenticação anterior deve ter validado o
 * token/sessão e preenchido `req.auth.companyId`. O tenant NUNCA é lido de
 * headers, query string ou body enviados pelo cliente, pois isso permitiria
 * a um usuário se passar por outra empresa.
 */

const ACTIVE_STATUSES = new Set(['active', 'trialing']);

class SubscriptionGuard {
  /**
   * @param {object}  opts
   * @param {string}  opts.billingBaseUrl      Ex.: https://billing.exemplo.com
   * @param {string}  opts.billingApiKey       Credencial do serviço de faturamento
   * @param {number} [opts.timeoutMs=2000]     Timeout da chamada ao faturamento
   * @param {number} [opts.cacheTtlMs=0]       TTL do cache (0 = consulta a cada requisição)
   * @param {number} [opts.staleGraceMs=300000] Tempo máx. para usar resposta antiga se o faturamento cair
   * @param {Set<string>} [opts.activeStatuses] Status que liberam o acesso
   * @param {object} [opts.logger=console]
   */
  constructor(opts) {
    if (!opts || !opts.billingBaseUrl || !opts.billingApiKey) {
      throw new Error('billingBaseUrl e billingApiKey são obrigatórios');
    }
    this.baseUrl = opts.billingBaseUrl.replace(/\/+$/, '');
    this.apiKey = opts.billingApiKey;
    this.timeoutMs = opts.timeoutMs ?? 2000;
    this.cacheTtlMs = opts.cacheTtlMs ?? 0;
    this.staleGraceMs = opts.staleGraceMs ?? 5 * 60 * 1000;
    this.activeStatuses = opts.activeStatuses ?? ACTIVE_STATUSES;
    this.logger = opts.logger ?? console;

    this.cache = new Map();     // companyId -> { active, status, fetchedAt }
    this.inFlight = new Map();  // companyId -> Promise (deduplica chamadas simultâneas)
  }

  /** Consulta o serviço de faturamento. Lança erro em falha de rede/timeout/resposta inválida. */
  async fetchSubscription(companyId) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const url = `${this.baseUrl}/v1/companies/${encodeURIComponent(companyId)}/subscription`;
      const res = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          Accept: 'application/json',
        },
        signal: controller.signal,
      });

      // Empresa sem assinatura registrada: resposta definitiva, não é falha do serviço.
      if (res.status === 404) {
        return { active: false, status: 'not_found' };
      }
      if (!res.ok) {
        throw new Error(`Faturamento respondeu HTTP ${res.status}`);
      }

      const body = await res.json();
      if (!body || typeof body.status !== 'string') {
        throw new Error('Resposta do faturamento em formato inesperado');
      }

      const status = body.status.toLowerCase();
      return { active: this.activeStatuses.has(status), status };
    } finally {
      clearTimeout(timer);
    }
  }

  /** Obtém o estado da assinatura usando cache curto e deduplicação de requisições concorrentes. */
  async getSubscription(companyId) {
    const now = Date.now();
    const cached = this.cache.get(companyId);

    if (cached && this.cacheTtlMs > 0 && now - cached.fetchedAt < this.cacheTtlMs) {
      return cached;
    }

    if (this.inFlight.has(companyId)) {
      return this.inFlight.get(companyId);
    }

    const promise = (async () => {
      try {
        const result = await this.fetchSubscription(companyId);
        const entry = { ...result, fetchedAt: Date.now() };
        this.cache.set(companyId, entry);
        return entry;
      } catch (err) {
        // Faturamento indisponível: tolera apenas um resultado anterior ainda dentro da janela de graça.
        if (cached && now - cached.fetchedAt < this.staleGraceMs) {
          this.logger.warn(
            `[subscriptionGuard] faturamento indisponível; usando resultado em cache (company=${companyId}): ${err.message}`
          );
          return cached;
        }
        throw err;
      } finally {
        this.inFlight.delete(companyId);
      }
    })();

    this.inFlight.set(companyId, promise);
    return promise;
  }

  /** Retorna o middleware propriamente dito. */
  middleware() {
    return async (req, res, next) => {
      const companyId = req.auth && req.auth.companyId;

      // Sem tenant autenticado: não há como avaliar a assinatura.
      if (!companyId) {
        return res.status(401).json({
          error: 'unauthenticated',
          message: 'Autenticação necessária.',
        });
      }

      try {
        const sub = await this.getSubscription(String(companyId));

        if (!sub.active) {
          return res.status(402).json({
            error: 'subscription_inactive',
            message: 'A assinatura da sua empresa não está ativa. Regularize para continuar.',
          });
        }

        req.subscription = { status: sub.status }; // disponível para handlers posteriores
        return next();
      } catch (err) {
        // Falha fechada: na dúvida, não libera o acesso.
        this.logger.error(
          `[subscriptionGuard] falha ao verificar assinatura (company=${companyId}): ${err.message}`
        );
        res.set('Retry-After', '5');
        return res.status(503).json({
          error: 'billing_unavailable',
          message: 'Não foi possível verificar a assinatura no momento. Tente novamente em instantes.',
        });
      }
    };
  }
}

/** Fábrica de conveniência. */
function createSubscriptionGuard(opts) {
  return new SubscriptionGuard(opts).middleware();
}

module.exports = { SubscriptionGuard, createSubscriptionGuard };

/* ------------------------------------------------------------------
 * EXEMPLO DE USO (Express)
 * ------------------------------------------------------------------
 *
 * const express = require('express');
 * const { createSubscriptionGuard } = require('./subscriptionGuard');
 * const authenticate = require('./authenticate'); // preenche req.auth.companyId
 *
 * const app = express();
 *
 * app.get('/health', (req, res) => res.send('ok')); // rota pública, fora do guard
 *
 * app.use(authenticate);
 * app.use(
 *   createSubscriptionGuard({
 *     billingBaseUrl: process.env.BILLING_URL,
 *     billingApiKey: process.env.BILLING_API_KEY,
 *     timeoutMs: 2000,
 *     cacheTtlMs: 0, // consulta a cada requisição; use 10_000–60_000 para reduzir carga
 *   })
 * );
 *
 * app.use('/api', require('./routes'));
 * app.listen(3000);
 */