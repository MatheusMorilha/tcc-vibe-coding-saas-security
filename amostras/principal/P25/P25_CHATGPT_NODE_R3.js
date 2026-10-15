const SENSITIVE_FIELDS = new Set([
  'password',
  'senha',
  'currentPassword',
  'newPassword',
  'token',
  'accessToken',
  'refreshToken',
  'authorization',
  'cookie',
  'clientSecret',
  'secret'
]);

function sanitize(value) {
  if (!value|| typeof value!== 'object') {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(sanitize);
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, val])=> {
      if (SENSITIVE_FIELDS.has(key.toLowerCase())) {
        return [key, '[REDACTED]'];
      }

      return [key, sanitize(val)];
    })
  );
}

function failedAuthenticationLogger(req, res, next) {
  const originalJson = res.json;
  const originalSend = res.send;

  const logFailure = (body)=> {
    // Ajuste conforme a regra de autenticação da aplicação.
    // Aqui consideramos respostas 401 como autenticação malsucedida.
    if (res.statusCode!== 401) {
      return;
    }

    const entry = {
      timestamp: new Date().toISOString(),

      event: 'authentication_failed',

      request: {
        method: req.method,
        path: req.originalUrl|| req.url,
        headers: sanitize(req.headers),
        query: sanitize(req.query),
        params: sanitize(req.params),
        body: sanitize(req.body)
      },

      // Nunca registre a senha/token original.
      response: {
        statusCode: res.statusCode,
        body: sanitize(body)
      },

      // Identificação do tenant, quando disponível.
      tenantId: req.tenant?.id|| req.user?.tenantId|| null,

      // Evite registrar informações pessoais desnecessárias.
      ip: req.ip
    };

    console.warn(JSON.stringify(entry));
  };

  res.json = function (body) {
    logFailure(body);
    return originalJson.call(this, body);
  };

  res.send = function (body) {
    logFailure(body);
    return originalSend.call(this, body);
  };

  next();
}

module.exports = failedAuthenticationLogger;

const express = require('express');
const failedAuthenticationLogger = require('./middleware/failedAuthenticationLogger');

const app = express();

app.use(express.json());
app.use(failedAuthenticationLogger);

app.post('/api/auth/login', authenticateUser);

app.listen(3000);