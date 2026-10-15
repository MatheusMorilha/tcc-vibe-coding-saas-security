const { AsyncLocalStorage } = require('async_hooks');
const crypto = require('crypto');
const winston = require('winston');

// 1. Armazenamento local assíncrono para isolar o contexto do tenant/request por chamada
const asyncLocalStorage = new AsyncLocalStorage();

// 2. Configuração do Winston para logs estruturados em JSON
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console()
  ]
});

/**
 * Lista de campos que devem ser mascarados por segurança/LGPD
 */
const SENSITIVE_FIELDS = ['password', 'token', 'authorization', 'secret', 'credit_card', 'cpf'];

/**
 * Funçao auxiliar para remover/mascarar dados sensíveis do payload ou headers
 */
function sanitize(data){
  if (!data || typeof data !== 'object') return data;

  const sanitized = Array.isArray(data) ? [...data] : { ...data };

  for (const key of Object.keys(sanitized)) {
    const lowerKey = key.toLowerCase();
    if (SENSITIVE_FIELDS.some(field => lowerKey.includes(field))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
      sanitized[key] = sanitize(sanitized[key]);
    }
  }

  return sanitized;
}

/**
 * Middleware para auditoria e log de requisições SaaS Multilocatário
 */
function requestAuditLogger(req, res, next){
  const startTime = process.hrtime();

  // Identificadores de rastreio e contexto multi-tenant
  const correlationId = req.headers['x-correlation-id'] || crypto.randomUUID();
  const tenantId = req.headers['x-tenant-id'] || req.user?.tenantId || 'anonymous';
  const userId = req.user?.id || req.headers['x-user-id'] || 'anonymous';

  // Injeta no header da resposta para rastreamento pelo cliente
  res.setHeader('X-Correlation-ID', correlationId);

  const context = { correlationId, tenantId, userId };

  // Executa a requisição dentro do contexto isolado do AsyncLocalStorage
  asyncLocalStorage.run(context, () => {
    // Intercepta o término da resposta para calcular tempo de execução e registrar o log
    res.on('finish', () => {
      const [seconds, nanoseconds] = process.hrtime(startTime);
      const durationMs = (seconds * 1000 + nanoseconds / 1e6).toFixed(2);

      const logPayload = {
        correlation_id: correlationId,
        tenant_id: tenantId,
        user_id: userId,
        request: {
          method: req.method,
          url: req.originalUrl || req.url,
          query: sanitize(req.query),
          params: sanitize(req.params),
          headers: sanitize({
            'user-agent': req.headers['user-agent'],
            'x-forwarded-for': req.headers['x-forwarded-for'],
            host: req.headers['host']
          }),
          body: sanitize(req.body)
        },
        response: {
          status_code: res.statusCode,
          duration_ms: Number(durationMs)
        }
      };

      // Registra como WARN/ERROR caso o status indicativo de falha
      if (res.statusCode >= 500) {
        logger.error('API Request Failed (Server Error)', logPayload);
      } else if (res.statusCode >= 400) {
        logger.warn('API Request Warning (Client Error)', logPayload);
      } else {
        logger.info('API Request Processed', logPayload);
      }
    });

    next();
  });
}

module.exports = { requestAuditLogger, asyncLocalStorage, logger };