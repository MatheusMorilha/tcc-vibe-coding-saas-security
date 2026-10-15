const crypto = require('crypto');

function requestLogger(req, res, next) {
  const requestId = crypto.randomUUID();
  const startedAt = Date.now();

  const sanitize = (value)=> {
    if (!value|| typeof value!== 'object')return value;

    const sensitive = /password|token|authorization|cookie|secret|api[-_]?key/i;

    return Object.fromEntries(
      Object.entries(value).map(([key, val])=> [
        key,
        sensitive.test(key)? '[REDACTED]' : val
      ])
    );
  };

  const log = {
    requestId,
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    tenantId: req.user?.tenantId?? req.tenantId?? null,
    userId: req.user?.id?? null,
    headers: sanitize({
      'content-type': req.headers['content-type'],
      'user-agent': req.headers['user-agent']
    }),
    query: sanitize(req.query),
    params: sanitize(req.params),
    body: sanitize(req.body)
  };

  console.info(JSON.stringify(log));

  res.on('finish', ()=> {
    console.info(JSON.stringify({
      requestId,
      statusCode: res.statusCode,
      durationMs: Date.now()- startedAt
    }));
  });

  next();
}

module.exports = requestLogger;