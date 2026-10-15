const ALLOWED_ORIGINS = new Set([
  'https://app.cliente-a.com',
  'https://app.cliente-b.com'
]);

function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;

  if (origin&& ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET,POST,PUT,PATCH,DELETE,OPTIONS'
    );
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-Tenant-Id'
    );
  }

  if (req.method=== 'OPTIONS') {
    return res.status(204).end();
  }

  next();
}

module.exports = corsMiddleware;