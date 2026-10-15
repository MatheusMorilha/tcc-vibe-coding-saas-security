// src/errors/AppError.js
class AppError extends Error{
  /**
   * @param {string} message - Mensagem amigável para o cliente.
   * @param {number} statusCode - Código HTTP (ex: 400, 401, 403, 404).
   * @param {Object}[details=null] - Detalhes adicionais da validação ou contexto.
   */
  constructor(message, statusCode = 400, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.details = details;
    this.isOperational = true; // Identifica erros de negócio vs. erros não esperados

    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = AppError;

// src/middlewares/globalErrorHandler.js
const AppError = require('../errors/AppError');

/**
 * Middleware global de tratamento de erros
 */
const globalErrorHandler = (err, req, res, next) => {
  // Contexto do Tenant/Usuário extraído do request para auditoria e logs
  const tenantId = req.tenantId || req.headers['x-tenant-id'] || 'N/A';
  const userId = req.user?.id || 'Anônimo';

  // 1. Tratamento para erros de negócio conhecidos (AppError)
  if (err instanceof AppError) {
    // Log operacional de baixa/média gravidade
    console.warn(`[WARN] [Tenant: ${tenantId}] [User: ${userId}] ${err.statusCode} - ${err.message}`);

    return res.status(err.statusCode).json({
      status: 'error',
      message: err.message,
      ...(err.details && { details: err.details }),
      timestamp: new Date().toISOString()
    });
  }

  // 2. Trata erros conhecidos de bibliotecas terceiras (Ex: JWT, ORMs)
  if (err.name === 'UnauthorizedError' || err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      status: 'error',
      message: 'Token de autenticação inválido ou expirado.',
      timestamp: new Date().toISOString()
    });
  }

  if (err.name === 'ValidationError') {
    return res.status(422).json({
      status: 'error',
      message: 'Erro de validação nos dados enviados.',
      details: err.errors || err.details,
      timestamp: new Date().toISOString()
    });
  }

  // 3. Log crítico para erros não esperados (Ex: Falha de conexão com BD, Crash de código)
  console.error(`[CRITICAL ERROR] [Tenant: ${tenantId}] [User: ${userId}]`, {
    message: err.message,
    stack: err.stack,
    path: req.originalUrl,
    method: req.method,
  });

  // Em ambiente de produção, nunca expor a stack trace ou mensagem interna
  const isDevelopment = process.env.NODE_ENV === 'development';

  return res.status(500).json({
    status: 'error',
    message: 'Ocorreu um erro interno no servidor. Por favor, tente novamente mais tarde.',
    ...(isDevelopment && {
      internalMessage: err.message,
      stack: err.stack
    }),
    timestamp: new Date().toISOString()
  });
};

module.exports = globalErrorHandler;

// src/app.js
const express = require('express');
const globalErrorHandler = require('./middlewares/globalErrorHandler');
const AppError = require('./errors/AppError');

const app = express();
app.use(express.json());

// Exemplo de rota testando isolamento de Tenant/Assinatura
app.get('/api/v1/relatorios', async (req, res, next) => {
  try {
    const tenant = req.tenant; // Injetado previamente pelo middleware de tenant

    if (!tenant.hasActiveSubscription) {
      throw new AppError('Sua empresa não possui um plano de assinatura ativo.', 403);
    }

    // Lógica da rota...
    res.json({ data: [] });
  } catch (error) {
    next(error); // Encaminha para o globalErrorHandler
  }
});

// Tratador para rotas inexistentes (404)
app.use('*', (req, res, next) => {
  next(new AppError(`A rota ${req.originalUrl} não existe neste servidor.`, 404));
});

// Registro do Tratador Global de Erros (sempre ao final!)
app.use(globalErrorHandler);

module.exports = app;