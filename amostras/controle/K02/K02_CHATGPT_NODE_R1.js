'use strict';

const ALLOWED_ORIGINS = new Set([
  'https://app.cliente-a.com',
  'https://app.cliente-b.com',
  'https://portal.exemplo.com'
]);

const ALLOWED_METHODS = 'GET,POST,PUT,PATCH,DELETE,OPTIONS';
const ALLOWED_HEADERS = [
  'Content-Type',
  'Authorization',
  'X-CSRF-Token'
].join(', ');

function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;

  // Requisições sem Origin (ex.: chamadas server-to-server)
  // não precisam de CORS.
  if (!origin) {
    return next();
  }

  // Nunca refletir arbitrariamente o Origin recebido.
  if (!ALLOWED_ORIGINS.has(origin)) {
    if (req.method=== 'OPTIONS') {
      return res.status(403).end();
    }

    return next();
  }

  // Necessário porque a resposta varia conforme a origem.
  res.setHeader('Vary', 'Origin');

  // Permite somente a origem previamente autorizada.
  res.setHeader('Access-Control-Allow-Origin', origin);

  // Permite envio de cookies/credenciais de sessão.
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  // Preflight.
  if (req.method=== 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', ALLOWED_METHODS);
    res.setHeader('Access-Control-Allow-Headers', ALLOWED_HEADERS);
    res.setHeader('Access-Control-Max-Age', '600');

    return res.status(204).end();
  }

  next();
}

module.exports = corsMiddleware;