const winston = require('winston');

// Logger centralizado com formato JSON estruturado
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/api-audit.log' })
  ]
});

// Campos sensíveis que não devem ser salvos em texto puro
const SENSITIVE_FIELDS = ['password', 'senha', 'token', 'credit_card', 'authorization', 'secret'];

/**
 * Função utilitária para sanitizar objetos (remover/mascarar senhas e dados sensíveis)
 */
function sanitizeData(data){
  if (!data || typeof data !== 'object') return data;

  const sanitized = Array.isArray(data) ? [...data] : { ...data };

  for (const key of Object.keys(sanitized)) {
    if (SENSITIVE_FIELDS.includes(key.toLowerCase())) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof sanitized[key] === 'object') {
      sanitized[key] = sanitizeData(sanitized[key]);
    }
  }

  return sanitized;
}

/**
 * Middleware de Audit Log para SaaS Multilocatário
 */
function requestAuditLogger(req, res, next){
  const startTime = Date.now();

  // Intercepta a resposta para registrar os logs ao final da execução da requisição
  res.on('finish', () => {
    const durationMs = Date.now() - startTime;

    const logEntry = {
      timestamp: new Date().toISOString(),
      correlation_id: req.headers['x-request-id'] || req.id || null,

      // Contexto de Multilocatário (assumindo que o middleware de auth já populou req.user ou req.tenant)
      tenant_id: req.tenantId || req.user?.tenantId || req.headers['x-tenant-id'] || 'ANONYMOUS',
      user_id: req.user?.id || 'UNAUTHENTICATED',

      // Dados da Requisição
      request: {
        method: req.method,
        url: req.originalUrl || req.url,
        ip: req.ip || req.socket.remoteAddress,
        user_agent: req.get('user-agent'),
        query_params: sanitizeData(req.query),
        body: sanitizeData(req.body)
      },

      // Dados da Resposta
      response: {
        status_code: res.statusCode,
        duration_ms: durationMs
      }
    };

    // Classificação de nível de log de acordo com o status HTTP
    if (res.statusCode >= 500) {
      logger.error('API Request Error', logEntry);
    } else if (res.statusCode >= 400) {
      logger.warn('API Request Client Failure', logEntry);
    } else {
      logger.info('API Request Success', logEntry);
    }
  });

  next();
}

module.exports = requestAuditLogger;