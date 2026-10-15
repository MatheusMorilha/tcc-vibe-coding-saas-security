// src/errors/AppError.js

class AppError extends Error{
  constructor(message, statusCode = 500, errorCode = 'INTERNAL_SERVER_ERROR', details = null) {
    super(message);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.isOperational = true; // Identifica erros de regra de negócio vs falhas do sistema/infra
    this.details = details;

    Error.captureStackTrace(this, this.constructor);
  }
}

class TenantAccessDeniedError extends AppError{
  constructor(message = 'Acesso não autorizado aos dados da empresa especificada.') {
    super(message, 403, 'TENANT_ACCESS_DENIED');
  }
}

class SubscriptionPlanLimitError extends AppError{
  constructor(message = 'Limite do plano de assinatura atingido. Faça um upgrade para continuar.') {
    super(message, 402, 'SUBSCRIPTION_LIMIT_EXCEEDED');
  }
}

class NotFoundError extends AppError{
  constructor(message = 'Recurso não encontrado.') {
    super(message, 404, 'RESOURCE_NOT_FOUND');
  }
}

class ValidationError extends AppError{
  constructor(message = 'Dados de entrada inválidos.', details = null) {
    super(message, 400, 'VALIDATION_ERROR', details);
  }
}

module.exports = {
  AppError,
  TenantAccessDeniedError,
  SubscriptionPlanLimitError,
  NotFoundError,
  ValidationError,
};

// src/middlewares/errorHandler.js

const { AppError } = require('../errors/AppError');

/**
 * Middleware Global de Erros do Express.
 * Deve possuir exatamente 4 parâmetros (err, req, res, next) para ser reconhecido como Error Handler.
 */
function errorHandler(err, req, res, next){
  // Contexto do Tenant e Usuário injetado previamente pelos middlewares de Auth e TenantContext
  const tenantId = req.tenantId || req.headers['x-tenant-id'] || 'ANONYMOUS';
  const userId = req.user?.id || 'UNAUTHENTICATED';
  const requestId = req.headers['x-request-id'] || null;

  let statusCode = err.statusCode || 500;
  let errorCode = err.errorCode || 'INTERNAL_SERVER_ERROR';
  let message = err.message || 'Ocorreu um erro interno no servidor.';
  let details = err.details || null;

  // Trata falhas de parse de JSON corrompido no body da requisição
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    statusCode = 400;
    errorCode = 'INVALID_JSON_PAYLOAD';
    message = 'O corpo da requisição contém um JSON malformatado.';
  }

  // Trata erros de ORM / Banco de Dados (exemplo: violação de constraint de unicidade no DB)
  if (err.name === 'SequelizeUniqueConstraintError' || err.code === '23505') {
    statusCode = 409;
    errorCode = 'RESOURCE_ALREADY_EXISTS';
    message = 'Já existe um registro com os dados informados para esta empresa.';
  }

  const isOperational = err instanceof AppError ? err.isOperational : false;

  // Log estruturado enriquecido com contexto multi-tenant
  const logPayload = {
    timestamp: new Date().toISOString(),
    requestId,
    tenantId,
    userId,
    path: req.originalUrl,
    method: req.method,
    statusCode,
    errorCode,
    isOperational,
    message: err.message,
    stack: process.env.NODE_NODE_ENV === 'production' && isOperational ? undefined : err.stack,
  };

  if (statusCode >= 500) {
    console.error('[CRITICAL_ERROR]', JSON.stringify(logPayload));
  } else {
    console.warn('[APP_ERROR]', JSON.stringify(logPayload));
  }

  // Sanitização da resposta enviada ao cliente
  const response = {
    error: {
      code: errorCode,
      message: isOperational || process.env.NODE_ENV !== 'production'
        ? message
        : 'Ocorreu um erro interno ao processar a solicitação.',
      ...(details && { details }),
      ...(requestId && { requestId }),
    },
  };

  // Retorna o stack trace apenas em ambiente de desenvolvimento
  if (process.env.NODE_ENV === 'development' && !isOperational) {
    response.error.stack = err.stack;
  }

  return res.status(statusCode).json(response);
}

module.exports = errorHandler;

// src/app.js

const express = require('express');
const errorHandler = require('./middlewares/errorHandler');
const { SubscriptionPlanLimitError } = require('./errors/AppError');

const app = express();
app.use(express.json());

// Simulação de Middleware de Contexto do Tenant (injeta req.tenantId)
app.use((req, res, next) => {
  req.tenantId = req.headers['x-tenant-id'] || 'tenant_acme_123';
  next();
});

// Exemplo de Rota da Aplicação SaaS
app.post('/api/v1/users', async (req, res, next) => {
  try {
    const totalUsersInTenant = 10; // Exemplo de busca no DB
    const planLimit = 10;

    if (totalUsersInTenant >= planLimit) {
      throw new SubscriptionPlanLimitError(
        'Você atingiu o limite de 10 usuários do plano Starter.'
      );
    }

    return res.status(201).json({ success: true });
  } catch (err) {
    // Repassa o erro de rotas assíncronas para o tratador global
    next(err);
  }
});

// Rota de fallback para caminhos inexistentes (404)
app.use((req, res, next) => {
  const { NotFoundError } = require('./errors/AppError');
  next(new NotFoundError(`Rota não encontrada: ${req.method} ${req.originalUrl}`));
});

// Registro OBRIGATÓRIO do Handler Global no final de toda a pilha de rotas
app.use(errorHandler);

module.exports = app;