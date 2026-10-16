// src/middlewares/authAuditLogger.js
const crypto = require('crypto');

// Campos estritamente confidenciais que nunca devem ser expostos no log
const SENSITIVE_FIELDS = new Set([
  'password',
  'senha',
  'token',
  'refreshtoken',
  'access_token',
  'secret',
  'code',
  'mfa',
  'otp',
  'credit_card',
  'cvv'
]);

/**
 * Sanitiza recursivamente objetos removendo/mascarando credenciais
 * e evitando injeção de caracteres de controle.
 */
function sanitizePayload(payload, depth = 0){
  if (depth > 4 || payload === null || typeof payload !== 'object') {
    if (typeof payload === 'string') {
      // Remove caracteres CRLF para mitigar Log Injection
      return payload.replace(/[\r\n]/g, '').slice(0, 255);
    }
    return payload;
  }

  if (Array.isArray(payload)) {
    return payload.slice(0, 20).map(item => sanitizePayload(item, depth + 1));
  }

  const sanitized = {};
  for (const [key, value] of Object.entries(payload)) {
    const normalizedKey = key.toLowerCase().replace(/[^a-z0-9_]/g, '');

    if (SENSITIVE_FIELDS.has(normalizedKey)) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizePayload(value, depth + 1);
    } else if (typeof value === 'string') {
      // Limita tamanho para mitigar DoS por payload excessivo e remove CRLF
      sanitized[key] = value.replace(/[\r\n]/g, '').slice(0, 255);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

/**
 * Resolve o tenant a partir do cabeçalho customizado, subdomínio ou corpo da requisição.
 */
function resolveTenant(req){
  return (
    req.headers['x-tenant-id'] ||
    req.headers['x-tenant-slug'] ||
    (req.body && req.body.tenantId) ||
    (req.body && req.body.tenantSlug) ||
    'UNKNOWN_TENANT'
  );
}

/**
 * Middleware para auditoria de falhas de autenticação.
 * Pode ser aplicado especificamente nas rotas de login (ex: /api/v1/auth/login).
 */
function failedAuthLogger(req, res, next){
  const originalJson = res.json.bind(res);
  const originalSend = res.send.bind(res);
  const startTime = Date.now();
  let capturedResponseBody = null;

  // Intercepta a resposta JSON para inspecionar o status e payload de erro
  res.json = function (body){
    capturedResponseBody = body;
    return originalJson(body);
  };

  res.send = function (body){
    if (!capturedResponseBody) {
      capturedResponseBody = body;
    }
    return originalSend(body);
  };

  res.on('finish', () => {
    // 401: Unauthorized (Credenciais inválidas)
    // 403: Forbidden (Conta bloqueada, tenant inativo ou sem permissão de acesso)
    if (res.statusCode === 401 || res.statusCode === 403) {
      const clientIp = (
        req.headers['x-forwarded-for']?.split(',')[0] ||
        req.socket?.remoteAddress ||
        'UNKNOWN_IP'
      ).trim();

      const auditEvent = {
        timestamp: new Date().toISOString(),
        event: 'AUTH_FAILURE',
        requestId: req.headers['x-request-id'] || crypto.randomUUID(),
        tenantIdentifier: resolveTenant(req),
        http: {
          method: req.method,
          path: req.originalUrl || req.url,
          statusCode: res.statusCode,
          durationMs: Date.now() - startTime
        },
        client: {
          ip: clientIp,
          userAgent: (req.headers['user-agent'] || 'UNKNOWN').slice(0, 255)
        },
        requestData: {
          headers: {
            host: req.headers['host'],
            origin: req.headers['origin'],
            referer: req.headers['referer']
          },
          // Sanitização profunda do corpo enviado
          body: sanitizePayload(req.body)
        },
        failureDetails: {
          // Extrai apenas a mensagem de erro pública retornada pela API
          message:
            typeof capturedResponseBody === 'object' && capturedResponseBody?.message
              ? capturedResponseBody.message
              : 'Authentication failed'
        }
      };

      // Gravação estruturada em formato JSON (Stdout / Stream para agregadores como Datadog, CloudWatch ou ELK)
      // Em produção, utilize uma biblioteca como Pino ou Winston
      console.warn(JSON.stringify(auditEvent));
    }
  });

  next();
}

module.exports = failedAuthLogger;