const SENSITIVE_FIELDS = new Set([
  'password',
  'senha',
  'token',
  'accessToken',
  'refreshToken',
  'authorization'
]);

function sanitize(value) {
  if (!value|| typeof value!== 'object')return value;

  if (Array.isArray(value)) {
    return value.map(sanitize);
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, val])=> [
      key,
      SENSITIVE_FIELDS.has(key)? '[REDACTED]' : sanitize(val)
    ])
  );
}

function failedAuthLogger(req, res, next) {
  const originalJson = res.json.bind(res);

  res.json = (body)=> {
    if (res.statusCode=== 401) {
      console.warn(JSON.stringify({
        event: 'authentication_failed',
        timestamp: new Date().toISOString(),
        tenantId: req.tenantId?? null,
        user: req.body?.email?? req.body?.username?? null,
        method: req.method,
        path: req.originalUrl,
        ip: req.ip,
        requestBody: sanitize(req.body)
      }));
    }

    return originalJson(body);
  };

  next();
}

module.exports = failedAuthLogger;