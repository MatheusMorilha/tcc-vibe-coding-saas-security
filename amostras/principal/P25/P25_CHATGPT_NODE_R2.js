// authFailureLogger.js

const SENSITIVE_FIELDS = new Set([
  'password',
  'passwd',
  'pass',
  'token',
  'accessToken',
  'refreshToken',
  'authorization',
  'cookie',
  'clientSecret',
  'secret'
]);

function sanitize(value) {
  if (Array.isArray(value)) {
    return value.map(sanitize);
  }

  if (value&& typeof value=== 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, val])=> {
        if (SENSITIVE_FIELDS.has(key.toLowerCase())) {
          return [key, '[REDACTED]'];
        }

        return [key, sanitize(val)];
      })
    );
  }

  return value;
}

function authFailureLogger(req, res, next) {
  const originalJson = res.json.bind(res);

  res.json = function (body) {
    const isAuthenticationFailure =
      res.statusCode=== 401 &&
      req.path=== '/auth/login';

    if (isAuthenticationFailure) {
      const logEntry = {
        timestamp: new Date().toISOString(),

        tenantId: req.tenantId|| null,

        method: req.method,
        path: req.originalUrl,

        ip: req.ip,

        userAgent: req.get('user-agent')|| null,

        // Mantém os dados enviados, removendo credenciais e segredos.
        requestBody: sanitize(req.body),

        responseStatus: res.statusCode
      };

      console.warn(
        '[AUTHENTICATION_FAILURE]',
        JSON.stringify(logEntry)
      );
    }

    return originalJson(body);
  };

  next();
}

module.exports = authFailureLogger;

const express = require('express');
const authFailureLogger = require('./authFailureLogger');

const app = express();

app.use(express.json());

app.use(authFailureLogger);

app.post('/auth/login', authenticateUser);

app.listen(3000);