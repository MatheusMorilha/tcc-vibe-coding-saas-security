const winston = require('winston');

// 1. Configuração do Logger de Segurança
const auditLogger = winston.createLogger({
  level: 'warn',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/auth-failures.log' }),
    new winston.transports.Console() // Exibe no console para ambientes de dev
  ],
});

/**
 * Função utilitária para higienizar o payload da requisição,
 * removendo senhas e informações confidenciais antes do log.
 */
function sanitizeRequestBody(body){
  if (!body) return {};
  const sanitized = { ...body };

  // Lista de campos que NUNCA devem ir para o log
  const sensitiveFields = ['password', 'senha', 'token', 'secret', 'creditCard'];

  sensitiveFields.forEach((field) => {
    if (field in sanitized) {
      sanitized[field] = '[REDACTED]';
    }
  });

  return sanitized;
}

/**
 * Middleware para registrar tentativas de autenticação malsucedidas.
 * Captura a resposta do endpoint de login e grava o log se o status for 401 ou 403.
 */
function logFailedAuthAttempts(req, res, next){
  // Captura a referência do método res.send original
  const originalSend = res.send;

  // Intercepta a resposta da requisição
  res.send = function (body){
    // Restaura a função original do res.send
    res.send = originalSend;

    // Filtra apenas respostas de falha na autenticação/autorização (401 Unauthorized / 403 Forbidden)
    if (res.statusCode === 401 || res.statusCode === 403) {
      const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
      const tenantIdentifier = req.headers['x-tenant-id'] || req.body?.tenantDomain || 'desconhecido';

      auditLogger.warn('Tentativa de autenticação malsucedida', {
        event: 'AUTH_FAILURE',
        statusCode: res.statusCode,
        timestamp: new Date().toISOString(),
        tenantId: tenantIdentifier,
        ip: clientIp,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        method: req.method,
        requestBody: sanitizeRequestBody(req.body),
        // Registra o motivo da falha se a API retornar mensagem no body
        responseSummary: typeof body === 'string' ? safeJsonParse(body) : body,
      });
    }

    // Executa o envio normal da resposta ao cliente
    return res.send(body);
  };

  next();
}

function safeJsonParse(str){
  try {
    return JSON.parse(str);
  } catch (e) {
    return { message: str };
  }
}

module.exports = logFailedAuthAttempts;

const express = require('express');
const logFailedAuthAttempts = require('./middleware/logFailedAuthAttempts');

const app = express();
app.use(express.json());

// Rota de login de exemplo
app.post('/api/v1/auth/login', logFailedAuthAttempts, (req, res) => {
  const { email, password, tenantDomain } = req.body;

  // Exemplo de validação/autenticação
  const isAuthenticated = false; // Simulando falha de credenciais

  if (!isAuthenticated) {
    return res.status(401).json({
      error: 'CREDENTIALS_INVALID',
      message: 'E-mail ou senha incorretos.'
    });
  }

  return res.status(200).json({ token: 'jwt-token-aqui' });
});

app.listen(3000, () => {
  console.log('Servidor rodando na porta 3000');
});