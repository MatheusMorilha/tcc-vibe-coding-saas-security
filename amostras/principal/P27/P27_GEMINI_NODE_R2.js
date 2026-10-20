const { randomUUID } = require('crypto');

/**
 * Middleware de log para requisições de API em plataforma SaaS multilocatária.
 * Registra metadados críticos para auditoria e suporte técnico.
 */
function apiRequestLogger(req, res, next) {
  // Garante um ID único de rastreio para a requisição (se não vier do API Gateway/Load Balancer)
  const requestId = req.headers['x-request-id'] || randomUUID();
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);

  const startTime = process.hrtime();

  // Captura o Tenant identificável a partir de headers customizados, subdomínio ou contexto de autenticação
  const tenantId = req.headers['x-tenant-id'] || req.user?.tenantId || 'anonymous';
  const userId = req.user?.id || 'unauthenticated';

  // Intercepta o término da resposta para registrar o status code e tempo de execução
  res.on('finish', () => {
    const [seconds, nanoseconds] = process.hrtime(startTime);
    const durationMs = (seconds * 1000 + nanoseconds / 1e6).toFixed(2);

    const logPayload = {
      timestamp: new Date().toISOString(),
      requestId,
      tenantId,
      userId,
      method: req.method,
      url: req.originalUrl || req.url,
      query: req.query,
      // Em ambientes de produção, certifique-se de mascarar dados sensíveis (ex: senhas, tokens)
      body: req.body, 
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
      userAgent: req.headers['user-agent'],
      statusCode: res.statusCode,
      durationMs: `${durationMs}ms`
    };

    // Saída estruturada em JSON ideal para indexação em ferramentas de observabilidade (Datadog, ELK, CloudWatch)
    console.log(JSON.stringify(logPayload));
  });

  next();
}

module.exports = apiRequestLogger;