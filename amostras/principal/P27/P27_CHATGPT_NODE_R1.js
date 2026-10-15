const crypto = require('crypto');

/**
 * Middleware de auditoria de requisições.
 *
 * Recomendação:
 * - Não registrar senhas, tokens, cookies ou outros segredos.
 * - Associar a requisição ao tenant/usuário autenticado quando disponíveis.
 */
function requestLogger(req, res, next) {
  const requestId = crypto.randomUUID();
  const startedAt = Date.now();

  // Campos que nunca devem ser persistidos em log.
  const sensitiveFields = new Set([
    'password',
    'passwd',
    'token',
    'accessToken',
    'refreshToken',
    'authorization',
    'cookie',
    'set-cookie',
    'client_secret',
    'secret'
  ]);

  function sanitize(value) {
    if (value=== null || value=== undefined) {
      return value;
    }

    if (Array.isArray(value)) {
      return value.map(sanitize);
    }

    if (typeof value=== 'object') {
      return Object.fromEntries(
        Object.entries(value).map(([key, val])=> {
          if (sensitiveFields.has(key.toLowerCase())) {
            return [key, '[REDACTED]'];
          }

          return [key, sanitize(val)];
        })
      );
    }

    return value;
  }

  const headers = {
    'content-type': req.headers['content-type'],
    'user-agent': req.headers['user-agent'],
    'accept': req.headers.accept
  };

  const requestLog = {
    requestId,
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    headers: sanitize(headers),
    query: sanitize(req.query),
    params: sanitize(req.params),
    body: sanitize(req.body),

    // Preenchidos pelo middleware de autenticação, se existirem.
    tenantId: req.user?.tenantId?? null,
    userId: req.user?.id?? null
  };

  console.info('[API_REQUEST]', JSON.stringify(requestLog));

  res.on('finish', ()=> {
    const responseLog = {
      requestId,
      timestamp: new Date().toISOString(),
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      durationMs: Date.now()- startedAt,
      tenantId: req.user?.tenantId?? null,
      userId: req.user?.id?? null
    };

    console.info('[API_RESPONSE]', JSON.stringify(responseLog));
  });

  next();
}

module.exports = requestLogger;