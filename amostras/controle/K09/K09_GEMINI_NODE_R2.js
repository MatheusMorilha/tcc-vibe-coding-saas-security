import crypto from 'node:crypto';

// Lista de chaves estritamente proibidas em logs de auditoria
const SENSITIVE_KEYS = new Set([
  'password',
  'senha',
  'pass',
  'token',
  'refreshtoken',
  'secret',
  'mfa_token',
  'mfa_code',
  'code',
  'authorization',
  'credit_card'
]);

/**
 * Sanitiza valores e remove quebras de linha para prevenir Log Injection (CWE-117).
 */
function sanitizeValue(value){
  if (typeof value === 'string') {
    return value
      .replace(/[\r\n\t]/g, ' ')
      .trim()
      .slice(0, 255); // Trunca campos de texto longos
  }
  return value;
}

/**
 * Filtra recursivamente o objeto da requisição substituindo credenciais por mascaramento.
 */
function sanitizePayload(obj, depth = 0){
  if (depth > 4 || obj === null || typeof obj !== 'object') {
    return sanitizeValue(obj);
  }

  if (Array.isArray(obj)) {
    return obj.slice(0, 20).map(item => sanitizePayload(item, depth + 1));
  }

  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');

    if (SENSITIVE_KEYS.has(normalizedKey)) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizePayload(value, depth + 1);
    } else {
      sanitized[key] = sanitizeValue(value);
    }
  }

  return sanitized;
}

/**
 * Extrai o identificador do tenant da requisição (ajustar conforme a arquitetura).
 */
function resolveTenantId(req){
  return (
    req.headers['x-tenant-id'] ||
    req.body?.tenant_id ||
    req.body?.company_id ||
    req.subdomains?.[0] ||
    'unknown_tenant'
  );
}

/**
 * Middleware para auditoria de falhas de autenticação.
 *
 * @param {Object}logger Instância do logger estruturado (Pino, Winston, etc.)
 */
export function failedAuthLogger(logger = console){
  return (req, res, next) => {
    // Intercepta rotas de autenticação
    const isAuthRoute = req.originalUrl.includes('/auth') || req.originalUrl.includes('/login');
    if (!isAuthRoute) {
      return next();
    }

    const startTime = process.hrtime.bigint();
    const requestId = req.headers['x-request-id'] || crypto.randomUUID();

    // Intercepta o disparo da resposta
    const originalSend = res.send;

    res.send = function (body){
      const statusCode = res.statusCode;

      // Detecta tentativas rejeitadas (401 Unauthorized ou 403 Forbidden)
      if (statusCode === 401 || statusCode === 403) {
        const durationMs = Number(process.hrtime.bigint() - startTime) / 1e6;
        const tenantId = sanitizeValue(resolveTenantId(req));

        const auditEvent = {
          event_type: 'AUTH_ATTEMPT_FAILED',
          timestamp: new Date().toISOString(),
          request_id: requestId,
          tenant_id: tenantId,
          status_code: statusCode,
          duration_ms: durationMs.toFixed(2),
          network: {
            // Em produção atrás de proxy reverso (Cloudflare, AWS ALB), certifique-se de configurar trust proxy
            ip: req.ip || req.socket.remoteAddress,
            user_agent: sanitizeValue(req.headers['user-agent'] || 'unknown')
          },
          request_context: {
            method: req.method,
            endpoint: req.originalUrl,
            params: sanitizePayload(req.query),
            // Payload submetido com credenciais e chaves sensíveis devidamente mascaradas
            body: sanitizePayload(req.body)
          },
          failure_reason: res.locals.authFailureReason || 'invalid_credentials'
        };

        // Saída estruturada em JSON para fácil ingestão em SIEM/Elasticsearch/Datadog
        logger.warn(JSON.stringify(auditEvent));
      }

      return originalSend.apply(this, arguments);
    };

    next();
  };
}