const axios = require('axios');

// Cache em memória simples para evitar requisições idênticas na mesma janela de tempo
const subscriptionCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // Cache de 5 minutos

/**
 * Middleware para validação do status da assinatura da empresa (Tenant)
 */
async function checkSubscriptionMiddleware(req, res, next){
  try {
    // 1. Extrai o ID da empresa cliente (definido na autenticação prévia)
    const tenantId = req.tenantId || req.headers['x-tenant-id'];

    if (!tenantId) {
      return res.status(400).json({
        error: 'TENANT_NOT_IDENTIFIED',
        message: 'Identificador da empresa não informado na requisição.'
      });
    }

    // 2. Verifica o cache em memória local
    const now = Date.now();
    const cachedData = subscriptionCache.get(tenantId);

    if (cachedData && (now - cachedData.timestamp < CACHE_TTL_MS)) {
      if (!cachedData.isActive) {
        return res.status(402).json({
          error: 'SUBSCRIPTION_INACTIVE',
          message: 'O acesso à plataforma foi suspenso devido pendências na assinatura.'
        });
      }
      return next();
    }

    // 3. Consulta o serviço externo de faturamento (Timeout de segurança: 2.5s)
    const billingResponse = await axios.get(
      `${process.env.BILLING_SERVICE_URL}/v1/subscriptions/${tenantId}`,
      {
        headers: {
          'Authorization': `Bearer ${process.env.BILLING_SERVICE_API_KEY}`
        },
        timeout: 2500
      }
    );

    const isActive = billingResponse.data?.status === 'active';

    // 4. Atualiza o cache local
    subscriptionCache.set(tenantId, {
      isActive,
      timestamp: now
    });

    // 5. Bloqueia ou libera a requisição
    if (!isActive) {
      return res.status(402).json({
        error: 'SUBSCRIPTION_INACTIVE',
        message: 'O acesso à plataforma foi suspenso devido pendências na assinatura.'
      });
    }

    return next();

  } catch (error) {
    console.error(`[Billing Middleware Error] Tenant: ${req.tenantId}`, error.message);

    // Estratégia de Fallback: em caso de erro/timeout da API externa,
    // permite a requisição (fail-open) ou bloqueia (fail-closed)
    // Recomendado em SaaS: fail-open curto para não prejudicar a experiência do cliente ativo.
    return next();
  }
}

module.exports = checkSubscriptionMiddleware;