import express from 'express';
import axios from 'axios';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const BILLING_SERVICE_URL = process.env.BILLING_SERVICE_URL;
const BILLING_API_KEY = process.env.BILLING_API_KEY;

// Cliente HTTP configurado com timeout rigoroso para não travar a aplicação
const billingClient = axios.create({
  baseURL: BILLING_SERVICE_URL,
  timeout: 2000, // Timeout de 2 segundos
  headers: {
    'Authorization': `Bearer ${BILLING_API_KEY}`,
    'Content-Type': 'application/json',
  },
});

/**
 * Middleware para verificação do status da assinatura do tenant.
 */
export async function verifySubscriptionMiddleware(req, res, next){
  try {
    // 1. Extrai o ID do tenant (definido em middleware anterior de autenticação/identificação)
    const tenantId = req.tenantId || req.headers['x-tenant-id'];

    if (!tenantId) {
      return res.status(400).json({
        error: 'TenantIdentifierMissing',
        message: 'O identificador do locatário (tenant) é obrigatório.',
      });
    }

    const cacheKey = `tenant:subscription:${tenantId}`;

    // 2. Tenta recuperar o status diretamente do Cache
    let subscriptionStatus = await redis.get(cacheKey);

    // 3. Cache Miss: Consulta o serviço de faturamento se não estiver em cache
    if (!subscriptionStatus) {
      subscriptionStatus = await fetchSubscriptionFromBillingService(tenantId);

      // Armazena no Redis por 1 hora (3600 segundos) para evitar sobrecarga externa
      await redis.set(cacheKey, subscriptionStatus, 'EX', 3600);
    }

    // 4. Bloqueia o acesso caso a assinatura não esteja ativa
    if (subscriptionStatus !== 'ACTIVE' && subscriptionStatus !== 'TRIALING') {
      return res.status(402).json({
        error: 'PaymentRequired',
        message: 'Acesso suspenso. A assinatura da sua empresa encontra-se inativa ou pendente de pagamento.',
        status: subscriptionStatus
      });
    }

    // Assinatura válida: permite a continuidade do fluxo
    next();
  } catch (error) {
    console.error(`[BillingMiddleware Error] Tenant: ${req.tenantId}`, error.message);

    // Estratégia de resiliência (Fail-Open): Se o serviço de cobrança estiver fora,
    // permite a requisição e loga o alerta para não prejudicar os clientes.
    // Alternativamente, mude para Fail-Closed retornando status 503 conforme a regra do negócio.
    next();
  }
}

/**
 * Helper com Circuit Breaker / Fallback básico para consultar a API externa
 */
async function fetchSubscriptionFromBillingService(tenantId){
  try {
    const response = await billingClient.get(`/subscriptions/status`, {
      params: { tenantId },
    });

    return response.data.status; // Esperado: 'ACTIVE', 'PAST_DUE', 'CANCELED', etc.
  } catch (error) {
    throw new Error(`Falha ao comunicar com o serviço de faturamento: ${error.message}`);
  }
}