const winston = require('winston');

// Configuração do logger (exemplo utilizando Winston para saída estruturada em JSON)
const auditLogger = winston.createLogger({
  level: 'warn',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'auth-failures.log' }),
    new winston.transports.Console()
  ]
});

/**
 * Função utilitária para sanitizar dados sensíveis do body da requisição
 * Evita o vazamento de senhas brutas nos logs do suporte.
 */
function sanitizeRequestBody(body){
  if (!body || typeof body !== 'object') return body;

  const sanitized = { ...body };
  const sensitiveFields = ['password', 'senha', 'token', 'secret', 'credit_card'];

  for (const field of sensitiveFields) {
    if (field in sanitized) {
      sanitized[field] = '[REDACTED]';
    }
  }

  return sanitized;
}

/**
 * Middleware para registrar falhas de autenticação
 */
function logFailedAuthAttempts(req, res, next){
  // Captura o término da requisição HTTP para checar o status code enviado
  res.on('finish', () => {
    // Intercepta apenas respostas de erro de autenticação/autorização (401 Unauthorized / 403 Forbidden)
    if (res.statusCode === 401 || res.statusCode === 403) {
      const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
      const tenantIdentifier = req.headers['x-tenant-id'] || req.body?.tenantDomain || req.body?.slug || 'unknown_tenant';

      const failureLog = {
        event: 'AUTH_FAILURE',
        timestamp: new Date().toISOString(),
        tenantId: tenantIdentifier,
        responseStatusCode: res.statusCode,
        requestDetails: {
          method: req.method,
          url: req.originalUrl,
          ip: clientIp,
          userAgent: req.get('user-agent'),
          headers: {
            host: req.get('host'),
            origin: req.get('origin'),
            'x-tenant-id': req.headers['x-tenant-id']
          },
          // Parâmetros de rota e query string
          params: req.params,
          query: req.query,
          // Payload enviado sanitizado
          body: sanitizeRequestBody(req.body)
        }
      };

      auditLogger.warn('Tentativa de autenticação malsucedida detectada', failureLog);
    }
  });

  next();
}

module.exports = logFailedAuthAttempts;

const express = require('express');
const logFailedAuthAttempts = require('./logFailedAuthAttempts');

const app = express();
app.use(express.json());

// Registra o middleware globalmente ou apenas nas rotas de autenticação
app.use(logFailedAuthAttempts);

// Rota de Login Multi-tenant
app.post('/api/v1/auth/login', (req, res) => {
  const { email, password, tenantDomain } = req.body;

  // Lógica de autenticação fictícia
  const isValidUser = false; // Exemplo de falha

  if (!isValidUser) {
    return res.status(401).json({ error: 'Credenciais inválidas ou tenant incorreto' });
  }

  return res.status(200).json({ token: 'jwt_token_exemplo' });
});

app.listen(3000, () => console.log('Servidor rodando na porta 3000'));