import axios from 'axios';
import { validate as isUuid } from 'uuid';

// Cache simples em memória com TTL (em produção distribuída, use Redis)
const subscriptionCache = new Map();
const CACHE_TTL_MS = 60 * 1000; // 1 minuto de cache para mitigar DoS/latência excessiva

// Configuração segura do cliente HTTP externo
const BILLING_SERVICE_BASE_URL = process.env.BILLING_SERVICE_BASE_URL;
const BILLING_SERVICE_API_KEY = process.env.BILLING_SERVICE_API_KEY;

if (!BILLING_SERVICE_BASE_URL || !BILLING_SERVICE_API_KEY) {
  throw new Error('Configurações do serviço de faturamento não encontradas no ambiente.');
}

const billingClient = axios.create({
  baseURL: BILLING_SERVICE_BASE_URL,
  timeout: 3000, // Timeout estrito (3s) para evitar esgotamento de sockets
  headers: {
    'Authorization': `Bearer ${BILLING_SERVICE_API_KEY}`,
    'Content-Type': 'application/json',
    'User-Agent': 'SaaS-Tenant-Gateway/1.0'
  }
});

/**
 * Consulta o status da assinatura no serviço externo ou no cache.
 * @param {string}tenantId
 * @returns {Promise<boolean>}
 */
async function isSubscriptionActive(tenantId){
  const cached = subscriptionCache.get(tenantId);
  const now = Date.now();

  if (cached && cached.expiresAt > now) {
    return cached.isActive;
  }

  // Prevenção contra SSRF e Path Traversal: codificação explícita do parâmetro
  const sanitizedTenantId = encodeURIComponent(tenantId);

  const response = await billingClient.get(`/v1/subscriptions/${sanitizedTenantId}/status`);

  // Espera-se um payload estrito do serviço: { status: 'ACTIVE' | 'SUSPENDED' | 'CANCELED' }
  const isActive = response.data && response.data.status === 'ACTIVE';

  subscriptionCache.set(tenantId, {
    isActive,
    expiresAt: now + CACHE_TTL_MS
  });

  return isActive;
}

/**
 * Middleware para validação de assinatura e controle de acesso multilocatário.
 */
export async function enforceActiveSubscription(req, res, next){
  try {
    // 1. Identificação do Tenant (A01: Broken Access Control)
    // O tenantId DEVE vir do contexto de autenticação validado (ex: JWT decodificado),
    // NUNCA de parâmetros controlados arbitrariamente pelo cliente via query/headers comuns.
    const tenantId = req.user?.tenantId;

    if (!tenantId) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Contexto de locatário (tenant) não identificado.'
      });
    }

    // 2. Validação e Sanitização de Entrada (A03: Injection)
    if (typeof tenantId !== 'string' || !isUuid(tenantId)) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Identificador de locatário inválido.'
      });
    }

    // 3. Verificação no Serviço de Faturamento
    const active = await isSubscriptionActive(tenantId);

    if (!active) {
      return res.status(403).json({
        error: 'Payment Required',
        code: 'SUBSCRIPTION_INACTIVE',
        message: 'O acesso da empresa está suspenso devido ao plano de assinatura.'
      });
    }

    // Continua para o próximo handler se a assinatura estiver ativa
    return next();

  } catch (error) {
    // 4. Fail-Secure e Tratamento de Exceções (A05: Security Misconfiguration)
    // Registra o log detalhado internamente sem vazar detalhes para o cliente
    console.error(`[BILLING_CHECK_ERROR] Tenant: ${req.user?.tenantId || 'desconhecido'} -`, {
      message: error.message,
      status: error.response?.status
    });

    // Se o serviço de faturamento estiver indisponível (503/Timeout), adota-se postura defensiva:
    // bloqueia o acesso ou envia código padronizado sem vazar stack trace.
    return res.status(503).json({
      error: 'Service Unavailable',
      message: 'Não foi possível validar a assinatura no momento. Tente novamente mais tarde.'
    });
  }
}