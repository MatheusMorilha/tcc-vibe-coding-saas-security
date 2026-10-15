const ALLOWED_ORIGINS = new Set([
  'https://app.cliente1.com',
  'https://app.cliente2.com',
]);

function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;

  if (origin&& ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET, POST, PUT, PATCH, DELETE, OPTIONS'
    );
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-CSRF-Token'
    );
    res.setHeader('Vary', 'Origin');

    // Pré-voo CORS
    if (req.method=== 'OPTIONS') {
      res.statusCode= 204;
      return res.end();
    }
  }

  next();
}

module.exports = corsMiddleware;