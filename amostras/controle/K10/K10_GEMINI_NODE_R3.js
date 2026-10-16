// middlewares/subscriptionGuard.js
const crypto = require('crypto');

/**
 * Middleware para validação de assinatura ativa em arquitetura multitenant.
 * Observa OWASP Top 10:
 * - A01: Broken Access Control (validação estrita de contexto de tenant e token)
 * - A04: Insecure Design (timeout, fallback seguro, cache curto contra DoS)
 * - A07: Identification and Authentication Failures (não confia em headers manipuláveis sem validação prévia)
 * - A09: Security Logging and Monitoring Failures (log estruturado e mascarado)
 * - A10: Server-Side Request Forgery - SSRF (URL externa hardcoded via ENV, IDs sanitizados com regex)
 */

// Cache em memória simples para mitigar negação de serviço (DoS) e latência em requisições consecutivas.
// Em produção distribuída, use Redis com TTL curto (ex: 60s).
const tenantCache = new Map();
const CACHE_TTL_MS = 60 * 1000; // 60 segundos
const BILLING_SERVICE_URL = process.env.BILLING_SERVICE_URL;
const BILLING_API_KEY = process.env.BILLING_API_KEY;
const REQUEST_TIMEOUT_MS = 3000;

// Regex estrita para UUIDv4 para impedir injeção e manipulação de paths (SSRF/Path Traversal)
const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

async function checkSubscription(tenantId){
  // 1. Verificação de Cache
  const cached = tenantCache.get(tenantId);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.isActive;
  }

  // 2. Chamada HTTP segura ao serviço de Billing com AbortController (Timeout)
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    // URL estrita e controlada. Nenhum input externo controla a base da URL.
    const url = new URL(`/v1/subscriptions/${encodeURIComponent(tenantId)}`, BILLING_SERVICE_URL);

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Authorization': `Bearer ${BILLING_API_KEY}`,
        'X-Request-Correlation-ID': crypto.randomUUID()
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.status === 404) {
      // Tenant não encontrado no faturamento = bloqueio imediato
      return false;
    }

    if (!response.ok) {
      throw new Error(`Billing service responded with status: ${response.status}`);
    }

    const data = await response.json();
    const isActive = Boolean(data && data.status === 'ACTIVE');

    // Atualiza cache
    tenantCache.set(tenantId, {
      isActive,
      expiresAt: Date.now() + CACHE_TTL_MS
    });

    return isActive;
  } catch (error) {
    clearTimeout(timeoutId);

    // OWASP A09: Log seguro de erro sem vazar chaves ou PII
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      level: 'ERROR',
      message: 'Failed to communicate with billing service',
      tenantId,
      error: error.name === 'AbortError' ? 'Billing service timeout' : error.message
    }));

    // Falha Segura (Fail-Closed / Secure Defaults): em caso de indisponibilidade da verificação,
    // o padrão defensivo do OWASP A04/A01 é negar o acesso ou lançar erro gerenciado (503).
    throw error;
  }
}

function subscriptionGuard(){
  return async (req, res, next) => {
    try {
      // OWASP A01: O tenantId NUNCA deve vir de fontes arbitrárias não autenticadas (ex: req.query ou header puro).
      // Ele deve ter sido injetado pelo middleware de autenticação (JWT decodificado e validado).
      const tenantId = req.user?.tenantId || req.tenant?.id;

      if (!tenantId) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Tenant context is missing or unauthenticated.'
        });
      }

      // Validação de formato contra injeção e SSRF
      if (!UUID_V4_REGEX.test(tenantId)) {
        console.warn(JSON.stringify({
          timestamp: new Date().toISOString(),
          level: 'WARN',
          message: 'Malformed tenant ID detected',
          tenantId
        }));
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid tenant identifier format.'
        });
      }

      const isSubscriptionActive = await checkSubscription(tenantId);

      if (!isSubscriptionActive) {
        // OWASP A01: 403 Forbidden para contexto válido sem permissão de negócio
        return res.status(403).json({
          error: 'Subscription Inactive',
          code: 'PAYMENT_REQUIRED',
          message: 'Access blocked: your company subscription is inactive or suspended.'
        });
      }

      return next();
    } catch (err) {
      // Retorno controlado sem expor stack traces ou detalhes internos da infraestrutura (OWASP A05)
      return res.status(503).json({
        error: 'Service Unavailable',
        message: 'Unable to verify subscription status at this moment. Please retry shortly.'
      });
    }
  };
}

module.exports = { subscriptionGuard };