import axios from 'axios';
import { LRUCache } from 'lru-cache';

// Configuração do Cache Local (Mitigação de DoS e esgotamento de quota na API externa)
const subscriptionCache = new LRUCache({
  max: 5000,              // Limite máximo de tenants em memória
  ttl: 1000 * 60 * 5,     // 5 minutos de TTL (Time To Live)
  allowStale: false,
});

// UUID v4 regex para validação estrita de identificadores
const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Cliente HTTP dedicado com timeout rígido (Prevenção de Slowloris / Resource Exhaustion)
const billingClient = axios.create({
  baseURL: process.env.BILLING_SERVICE_URL, // Variável de ambiente validada
  timeout: 3000,                           // 3 segundos de timeout
  headers: {
    'Authorization': `Bearer ${process.env.BILLING_SERVICE_API_KEY}`,
    'Content-Type': 'application/json',
    'User-Agent': 'SaaS-Core-Backend/1.0',
  },
});

/**
 * Consulta a API externa de faturamento de forma segura.
 * @param {string}tenantId
 * @returns {Promise<boolean>}
 */
async function fetchSubscriptionStatus(tenantId){
  // OWASP A10: Server-Side Request Forgery (SSRF)
  // O path é montado estritamente com o tenantId previamente validado via regex.
  const response = await billingClient.get(`/v1/customers/${encodeURIComponent(tenantId)}/subscription`);

  if (response.status === 200 && response.data) {
    const status = response.data.status;
    // Considera ativo apenas status explicitamente permitidos
    return status === 'active' || status === 'trialing';
  }

  return false;
}

/**
 * Middleware para validação do status da assinatura do tenant.
 */
export async function requireActiveSubscription(req, res, next){
  try {
    // OWASP A01: Broken Access Control
    // O tenantId NUNCA deve vir de cabeçalhos livres informados pelo cliente (ex: x-tenant-id)
    // sem assinatura criptográfica. Deve vir exclusivamente do contexto autenticado (ex: token JWT decodificado).
    const tenantId = req.user?.tenantId;

    if (!tenantId || typeof tenantId !== 'string' || !UUID_V4_REGEX.test(tenantId)) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Contexto de locatário ausente ou inválido.',
      });
    }

    // 1. Verificação no cache local
    const cachedStatus = subscriptionCache.get(tenantId);
    if (cachedStatus !== undefined) {
      if (!cachedStatus) {
        return res.status(402).json({
          error: 'Payment Required',
          message: 'Acesso bloqueado: assinatura suspensa ou cancelada.',
        });
      }
      return next();
    }

    // 2. Consulta à API externa de billing
    const isActive = await fetchSubscriptionStatus(tenantId);

    // 3. Atualização do cache com o resultado
    subscriptionCache.set(tenantId, isActive);

    if (!isActive) {
      return res.status(402).json({
        error: 'Payment Required',
        message: 'Acesso bloqueado: assinatura suspensa ou cancelada.',
      });
    }

    return next();
  } catch (error) {
    // OWASP A09: Security Logging and Monitoring Failures
    // Log interno estruturado para auditoria técnica (não exposto ao cliente)
    console.error('[SECURITY][BILLING_CHECK_FAILED]', {
      tenantId: req.user?.tenantId,
      error: error.message,
      timestamp: new Date().toISOString(),
    });

    // OWASP A05: Security Misconfiguration / Tratamento Seguro de Erros
    // Política de segurança: Fail-Closed (se o serviço de billing estiver fora,
    // a aplicação não deve liberar acesso não autorizado por padrão).
    return res.status(503).json({
      error: 'Service Unavailable',
      message: 'Não foi possível validar o status da assinatura no momento. Tente novamente mais tarde.',
    });
  }
}