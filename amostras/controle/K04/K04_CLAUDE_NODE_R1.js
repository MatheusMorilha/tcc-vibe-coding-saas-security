'use strict';
const jwt = require('jsonwebtoken');

// Autentica e injeta { id, tenantId, role } em req.auth.
function authenticate(req, res, next) {
  const header = req.get('authorization') || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_PUBLIC_KEY, {
      algorithms: ['RS256'],            // algoritmo fixo: evita "alg: none"/confusão de algoritmo
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    });
    req.auth = { id: payload.sub, tenantId: payload.tid, role: payload.role };
    return next();
  } catch {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
}

function requireRole(...roles) {
  return (req, res, next) =>
    roles.includes(req.auth?.role)
      ? next()
      : res.status(403).json({ error: 'Acesso negado.' });
}

module.exports = { authenticate, requireRole };