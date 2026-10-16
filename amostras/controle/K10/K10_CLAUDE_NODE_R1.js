'use strict';

/**
 * subscriptionGuard.js
 *
 * Middleware que consulta o serviço externo de faturamento a cada requisição
 * (com coalescência de chamadas concorrentes e cache opcional de TTL curto)
 * e libera/bloqueia o acesso conforme o status da assinatura da empresa.
 *
 * Requisitos: Node.js >= 18 (fetch e AbortSignal.timeout nativos).
 *
 * PRÉ-CONDIÇÃO: um middleware de autenticação anterior deve popular
 *   req.auth.tenantId  (a partir de JWT/sessão VERIFICADOS no servidor).
 * O tenantId NUNCA é lido de headers, query string ou body (OWASP A01).
 */

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const MAX_BODY_BYTES = 16 * 1024; // limita resposta do serviço externo

class BillingError extends Error {
  constructor(message, { status } = {}) {
    super(message);
    this.name = 'BillingError';
    this.status = status;
  }
}

/** Lê o corpo da resposta com limite de tamanho (evita consumo excessivo de memória). */
async function readLimitedText(res, limit) {
  const reader = res.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let received = 0;
  let text = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > limit) {
      await reader.cancel();
      throw new BillingError('Resposta do faturamento excede o limite');
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

function createSubscriptionGuard(options = {}) {
  const {
    baseUrl = process.env.BILLING_API_URL,
    apiKey = process.env.BILLING_API_KEY, // segredo vem do ambiente/secret manager (A02)
    timeoutMs = 3000,
    // 0 = consulta o faturamento em TODA requisição (comportamento estrito).
    // Valores pequenos (ex.: 15000-60000) reduzem carga, ao custo de atraso
    // na propagação de cancelamentos.
    cacheTtlMs = 0,
    // Tolerância a indisponibilidade do faturamento: reutiliza um "ativo"
    // conhecido por no máximo este tempo. 0 = fail-closed puro.
    staleGraceMs = 0,
    maxCacheEntries = 10_000,
    allowedStatuses = ['active'], // allowlist explícita (ex.: adicionar 'trialing')
    // Rotas isentas (comparação EXATA, definida em código, não por input do cliente)
    bypassPaths = ['/health'],
    logger = console,
  } = options;

  // ---------- Validação de configuração (falha no boot, não em runtime) ----------
  if (!baseUrl || !apiKey) {
    throw new Error('BILLING_API_URL e BILLING_API_KEY são obrigatórios');
  }
  const base = new URL(baseUrl);
  if (base.protocol !== 'https:') {
    throw new Error('O serviço de faturamento deve ser acessado via HTTPS (A02)');
  }
  const allowed = new Set(allowedStatuses);
  const bypass = new Set(bypassPaths);

  /** tenantId -> { active: boolean, at: number } */
  const cache = new Map();
  /** tenantId -> Promise<boolean> (coalescência de requisições concorrentes) */
  const inflight = new Map();

  function cacheSet(tenantId, active) {
    cache.delete(tenantId);
    if (cache.size >= maxCacheEntries) {
      cache.delete(cache.keys().next().value); // descarta o mais antigo
    }
    cache.set(tenantId, { active, at: Date.now() });
  }

  async function fetchSubscriptionActive(tenantId) {
    // URL montada a partir de base fixa + segmento codificado (previne SSRF/path traversal, A10:2021)
    const url = new URL(
      `${base.pathname.replace(/\/$/, '')}/v1/tenants/${encodeURIComponent(tenantId)}/subscription`,
      base.origin
    );
    if (url.origin !== base.origin) {
      throw new BillingError('Origem da URL inválida');
    }

    let res;
    try {
      res = await fetch(url, {
        method: 'GET',
        redirect: 'error', // não segue redirecionamentos
        headers: {
          Authorization: `Bearer ${apiKey}`,
          Accept: 'application/json',
        },
        signal: AbortSignal.timeout(timeoutMs), // timeout obrigatório
      });
    } catch (err) {
      throw new BillingError(`Falha de rede/timeout: ${err.name}`);
    }

    // Tenant sem assinatura registrada: resposta definitiva "inativa"
    if (res.status === 404) {
      if (res.body) await res.body.cancel();
      return false;
    }
    if (!res.ok) {
      if (res.body) await res.body.cancel();
      throw new BillingError('Resposta inesperada do faturamento', { status: res.status });
    }
    if (!(res.headers.get('content-type') || '').toLowerCase().includes('application/json')) {
      if (res.body) await res.body.cancel();
      throw new BillingError('Content-Type inesperado');
    }

    let data;
    try {
      data = JSON.parse(await readLimitedText(res, MAX_BODY_BYTES));
    } catch (err) {
      if (err instanceof BillingError) throw err;
      throw new BillingError('JSON inválido do faturamento');
    }

    // Validação estrita do contrato e da integridade (A08): a resposta deve
    // referir-se exatamente ao tenant consultado.
    if (
      !data ||
      typeof data !== 'object' ||
      typeof data.status !== 'string' ||
      typeof data.tenantId !== 'string' ||
      data.tenantId.toLowerCase() !== tenantId.toLowerCase()
    ) {
      throw new BillingError('Contrato de resposta inválido');
    }

    return allowed.has(data.status);
  }

  /** Retorna boolean (assinatura ativa) ou lança BillingError (indisponível). */
  async function isSubscriptionActive(tenantId) {
    const now = Date.now();
    const cached = cache.get(tenantId);

    if (cached && cacheTtlMs > 0 && now - cached.at <= cacheTtlMs) {
      return cached.active;
    }

    let pending = inflight.get(tenantId);
    if (!pending) {
      pending = fetchSubscriptionActive(tenantId)
        .then((active) => {
          cacheSet(tenantId, active); // só resultados definitivos entram no cache
          return active;
        })
        .finally(() => inflight.delete(tenantId));
      inflight.set(tenantId, pending);
    }

    try {
      return await pending;
    } catch (err) {
      // Degradação controlada: só reaproveita um "ATIVO" recente, nunca um "inativo".
      if (staleGraceMs > 0 && cached && cached.active && now - cached.at <= staleGraceMs) {
        logger.warn('[billing] indisponível; usando estado ativo recente', {
          tenantId,
          reason: err.message,
        });
        return true;
      }
      throw err;
    }
  }

  // ------------------------------- Middleware -------------------------------
  return async function subscriptionGuard(req, res, next) {
    try {
      res.setHeader('Cache-Control', 'no-store');

      if (bypass.has(req.path)) return next();

      // Identidade do tenant vem SOMENTE da autenticação já verificada (A01/A07)
      const tenantId = req.auth && req.auth.tenantId;
      if (typeof tenantId !== 'string' || !UUID_RE.test(tenantId)) {
        return res.status(401).json({ error: 'unauthorized' });
      }

      let active;
      try {
        active = await isSubscriptionActive(tenantId);
      } catch (err) {
        // Fail-closed (A04/A10:2025): sem confirmação, não libera.
        // Log interno sem segredos nem payloads; resposta genérica ao cliente (A05/A09).
        logger.error('[billing] erro ao verificar assinatura', {
          tenantId,
          requestId: req.id,
          reason: err.message,
          upstreamStatus: err.status,
        });
        res.setHeader('Retry-After', '5');
        return res.status(503).json({ error: 'billing_unavailable' });
      }

      if (!active) {
        logger.warn('[billing] acesso bloqueado: assinatura inativa', {
          tenantId,
          requestId: req.id,
        });
        return res.status(402).json({ error: 'subscription_inactive' });
      }

      return next();
    } catch (err) {
      // Qualquer exceção inesperada também bloqueia (fail-closed) sem vazar detalhes
      logger.error('[billing] falha inesperada no middleware', { reason: err.message });
      return res.status(500).json({ error: 'internal_error' });
    }
  };
}

module.exports = { createSubscriptionGuard, BillingError };

/* ------------------------------ Exemplo de uso ------------------------------

const express = require('express');
const { createSubscriptionGuard } = require('./subscriptionGuard');
const authenticate = require('./authenticate'); // verifica JWT e define req.auth.tenantId

const app = express();
app.disable('x-powered-by');

app.use(authenticate);                       // 1) autentica e define o tenant
app.use(createSubscriptionGuard({            // 2) verifica a assinatura
  cacheTtlMs: 0,
  staleGraceMs: 0,
  allowedStatuses: ['active'],
  bypassPaths: ['/health'],
}));
app.use('/api', apiRouter);                  // 3) rotas de negócio

------------------------------------------------------------------------------ */