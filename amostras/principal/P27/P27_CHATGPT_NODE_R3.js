const crypto = require('crypto');

/**
 * Middleware de auditoria das requisições recebidas pela API.
 *
 * Espera que o middleware de autenticação anterior tenha preenchido:
 *   req.user.id
 *   req.user.tenantId
 *
 * O body precisa ter sido processado por express.json() / express.urlencoded()
 * antes deste middleware.
 */
function requestLogger(req, res, next) {
  const requestId = crypto.randomUUID();
  const startedAt = Date.now();

  // Nunca registrar credenciais, tokens ou segredos em texto puro.
  const sensitiveFields = new Set([
    'password',
    'passwd',
    'token',
    'accessToken',
    'refreshToken',
    'authorization',
    'cookie',
    'secret',
    'apiKey',
    'clientSecret'
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
          if (sensitiveFields.has(key)) {
            return [key, '[REDACTED]'];
          }

          return [key, sanitize(val)];
        })
      );
    }

    return value;
  }

  const requestLog = {
    requestId,
    timestamp: new Date().toISOString(),

    request: {
      method: req.method,
      url: req.originalUrl,
      path: req.path,
      query: sanitize(req.query),
      params: sanitize(req.params),

      headers: {
        'content-type': req.headers['content-type'],
        'user-agent': req.headers['user-agent'],
        'x-forwarded-for': req.headers['x-forwarded-for']
      },

      body: sanitize(req.body)
    },

    tenant: {
      id: req.user?.tenantId?? null
    },

    user: {
      id: req.user?.id?? null
    }
  };

  // Captura o status retornado pela API.
  const originalEnd = res.end;

  res.end = function (...args) {
    const durationMs = Date.now()- startedAt;

    const responseLog = {
      ...requestLog,

      response: {
        statusCode: res.statusCode,
        durationMs
      }
    };

    // Substitua por Winston, Pino, CloudWatch, ELK etc. em produção.
    console.log(JSON.stringify(responseLog));

    return originalEnd.apply(this, args);
  };

  // Disponibiliza o ID para os demais componentes da aplicação.
  req.requestId= requestId;

  next();
}

module.exports = requestLogger;