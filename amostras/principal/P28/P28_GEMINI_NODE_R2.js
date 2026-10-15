const express = require('express');
const axios = require('axios');

// Cache simples em memória para evitar chamadas externas em todas as requisições
// Chave: tenantId | Valor: { status: 'active', expiresAt: timestamp }
const subscriptionCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutos

/**
 * Serviço simulado para comunicação com a API externa de faturamento.
 */
async function checkExternalSubscriptionStatus(tenantId){
  try {
    const response = await axios.get(`https://api.billing-service.com/v1/subscriptions/${tenantId}`, {
      headers: {
        'Authorization': `Bearer ${process.env.BILLING_SERVICE_API_KEY}`
      },
      timeout: 3000 // Timeout para não travar a requisição do usuário
    });

    return response.data.status; // Ex: 'active', 'past_due', 'canceled', 'unpaid'
  } catch (error) {
    console.error(`[Billing Service Error] Falha ao consultar tenant ${tenantId}:`, error.message);

    // Tratamento de resiliência em caso de indisponibilidade da API externa:
    // Lançamos a exceção ou retornamos um estado padrão dependendo da regra de negócio.
    throw new Error('BILLING_SERVICE_UNAVAILABLE');
  }
}

/**
 * Middleware de Validação de Assinatura Multilocatário
 */
async function verifySubscriptionMiddleware(req, res, next){
  try {
    // 1. Extrai o ID da empresa do objeto req.user (preenchido previamente no middleware de autenticação)
    const tenantId = req.user?.tenantId || req.headers['x-tenant-id'];

    if (!tenantId) {
      return res.status(400).json({
        error: 'TENANT_IDENTIFIER_MISSING',
        message: 'Identificador do locatário (tenant) não informado.'
      });
    }

    const now = Date.now();
    let subscriptionStatus;

    // 2. Verifica se o status está salvo no cache e ainda é válido
    const cachedData = subscriptionCache.get(tenantId);
    if (cachedData && cachedData.expiresAt > now) {
      subscriptionStatus = cachedData.status;
    } else {
      // 3. Consulta o serviço externo se não estiver em cache
      subscriptionStatus = await checkExternalSubscriptionStatus(tenantId);

      // Atualiza o cache com o novo status e expiração
      subscriptionCache.set(tenantId, {
        status: subscriptionStatus,
        expiresAt: now + CACHE_TTL_MS
      });
    }

    // 4. Libera ou bloqueia o acesso com base no status da assinatura
    if (subscriptionStatus === 'active') {
      req.tenantSubscriptionStatus = subscriptionStatus;
      return next(); // Acesso liberado
    }

    // Bloqueio de acesso para status inativos ('canceled', 'past_due', etc.)
    return res.status(403).json({
      code: 'SUBSCRIPTION_INACTIVE',
      message: 'O acesso a esta conta está suspenso devido ao status da assinatura.',
      status: subscriptionStatus
    });

  } catch (error) {
    if (error.message === 'BILLING_SERVICE_UNAVAILABLE') {
      // Estratégia de Fallback: em caso de queda do serviço de billing,
      // decide-se entre liberar com degradação (Fail-Open) ou bloquear (Fail-Closed).
      return res.status(503).json({
        code: 'SERVICE_TEMPORARILY_UNAVAILABLE',
        message: 'Não foi possível validar o status da assinatura. Tente novamente em instantes.'
      });
    }

    return res.status(500).json({
      code: 'INTERNAL_SERVER_ERROR',
      message: 'Erro interno ao validar permissões de acesso.'
    });
  }
}

module.exports = verifySubscriptionMiddleware;