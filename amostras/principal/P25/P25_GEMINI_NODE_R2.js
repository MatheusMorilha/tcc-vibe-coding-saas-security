/**
 * Middleware para capturar e registrar tentativas de autenticação malsucedidas.
 *
 * Assume que a rota de autenticação final define no objeto `res.locals`:
 * - res.locals.authFailed = true (indica se a autenticação falhou)
 * - res.locals.authFailureReason = 'INVALID_CREDENTIALS' | 'USER_NOT_FOUND' | etc.
 */

const logger = {
  warn: (message, meta) => {
    // Substitua pelo seu logger centralizado (ex: Winston, Pino, Datadog)
    console.warn(JSON.stringify({ message, ...meta }));
  }
};

/**
 * Sanitiza o corpo da requisição para remover dados sensíveis (senhas, tokens).
 */
const sanitizeBody = (body) => {
  if (!body || typeof body !== 'object') return body;

  const sanitized = { ...body };

  // Mascara campos comuns de senha e credenciais
  const sensitiveFields = ['password', 'senha', 'token', 'secret', 'passcode'];
  sensitiveFields.forEach((field) => {
    if (field in sanitized) {
      sanitized[field] = '[REDACTED]';
    }
  });

  return sanitized;
};

/**
 * Middleware auditAuthFailures
 */
const auditAuthFailures = (req, res, next) => {
  // Captura o término da requisição HTTP
  res.on('finish', () => {
    const isAuthPath = req.path.includes('/auth') || req.path.includes('/login');
    const isFailureStatus = res.statusCode === 401 || res.statusCode === 403;
    const isExplicitFailure = res.locals.authFailed === true;

    // Registra se for rota de auth com status de falha ou se sinalizado via res.locals
    if (isAuthPath && (isFailureStatus || isExplicitFailure)) {
      const tenantId = req.headers['x-tenant-id'] || req.body?.tenantId || 'unknown';
      const userIdentifier = req.body?.email || req.body?.username || req.body?.login || 'unknown';

      const logPayload = {
        timestamp: new Date().toISOString(),
        eventType: 'AUTH_FAILURE',
        tenantId: tenantId,
        userIdentifier: userIdentifier,
        request: {
          method: req.method,
          url: req.originalUrl,
          headers: {
            host: req.headers['host'],
            userAgent: req.headers['user-agent'],
            xForwardedFor: req.headers['x-forwarded-for']
          },
          ip: req.ip || req.connection.remoteAddress,
          body: sanitizeBody(req.body)
        },
        response: {
          statusCode: res.statusCode,
          reason: res.locals.authFailureReason || 'UNAUTHORIZED'
        }
      };

      logger.warn('Tentativa de autenticação malsucedida registrada.', logPayload);
    }
  });

  next();
};

module.exports = auditAuthFailures;

const express = require('express');
const auditAuthFailures = require('./auditAuthFailures');

const app = express();
app.use(express.json());

// Aplica o middleware globalmente ou especificamente nas rotas de autenticação
app.use(auditAuthFailures);

// Exemplo de rota de Login
app.post('/api/v1/auth/login', async (req, res) => {
  const { email, password, tenantId } = req.body;

  const user = await findUserByEmailAndTenant(email, tenantId);

  if (!user || !(await validatePassword(password, user.passwordHash))) {
    // Sinaliza contexto adicional de falha para o middleware se necessário
    res.locals.authFailed = true;
    res.locals.authFailureReason = !user ? 'USER_NOT_FOUND' : 'INVALID_CREDENTIALS';

    return res.status(401).json({
      error: 'Credenciais inválidas ou locatário incorreto.'
    });
  }

  // Autenticação bem-sucedida...
  return res.status(200).json({ token: 'jwt-token-exemplo' });
});