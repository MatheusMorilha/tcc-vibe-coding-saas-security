'use strict';

const { randomUUID } = require('node:crypto');

/* -------------------------------------------------------------------------- */
/* 1. Erros de domínio                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Erro "operacional": esperado, com mensagem segura para o cliente.
 * Qualquer outro erro é tratado como bug/falha de infraestrutura e NUNCA
 * tem sua mensagem exposta.
 */
class AppError extends Error {
  constructor(statusCode, code, message, { details, headers, cause } = {}) {
    super(message, { cause });
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.headers = headers;
    this.isOperational = true;
    Error.captureStackTrace?.(this, this.constructor);
  }
}

const Errors = {
  badRequest: (msg = 'Requisição inválida.', details) =>
    new AppError(400, 'BAD_REQUEST', msg, { details }),
  validation: (details, msg = 'Dados inválidos.') =>
    new AppError(422, 'VALIDATION_ERROR', msg, { details }),
  unauthorized: (msg = 'Autenticação necessária.') =>
    new AppError(401, 'UNAUTHORIZED', msg, {
      headers: { 'WWW-Authenticate': 'Bearer' },
    }),
  forbidden: (msg = 'Você não tem permissão para esta ação.') =>
    new AppError(403, 'FORBIDDEN', msg),
  // Recurso inexistente OU pertencente a outro tenant: mesma resposta,
  // para não revelar a existência de dados de outras empresas.
  notFound: (msg = 'Recurso não encontrado.') =>
    new AppError(404, 'NOT_FOUND', msg),
  conflict: (msg = 'Conflito com o estado atual do recurso.') =>
    new AppError(409, 'CONFLICT', msg),
  paymentRequired: (msg = 'Assinatura inativa ou inadimplente.') =>
    new AppError(402, 'SUBSCRIPTION_INACTIVE', msg),
  planLimit: (msg = 'Seu plano não permite esta operação.', details) =>
    new AppError(403, 'PLAN_LIMIT_EXCEEDED', msg, { details }),
  tooManyRequests: (retryAfterSeconds = 60) =>
    new AppError(429, 'RATE_LIMITED', 'Muitas requisições. Tente novamente em instantes.', {
      headers: { 'Retry-After': String(retryAfterSeconds) },
    }),
};

/* -------------------------------------------------------------------------- */
/* 2. Contexto da requisição (request id)                                     */
/* -------------------------------------------------------------------------- */

const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{8,64}$/;

/** Registrar ANTES das rotas. Aceita x-request-id apenas se for seguro. */
function requestContext(req, res, next) {
  const incoming = req.headers['x-request-id'];
  req.id = typeof incoming === 'string' && SAFE_REQUEST_ID.test(incoming)
    ? incoming
    : randomUUID();
  res.setHeader('X-Request-Id', req.id);
  next();
}

/* -------------------------------------------------------------------------- */
/* 3. Normalização: qualquer coisa lançada -> { status, code, message, ... }  */
/* -------------------------------------------------------------------------- */

const INTERNAL = Object.freeze({
  status: 500,
  code: 'INTERNAL_ERROR',
  message: 'Erro interno. Informe o identificador da requisição ao suporte.',
});

function normalizeError(err) {
  // 3.1 Erros de domínio
  if (err instanceof AppError) {
    return {
      status: err.statusCode,
      code: err.code,
      message: err.message,
      details: err.details,
      headers: err.headers,
    };
  }

  // 3.2 Parser de body (body-parser / express.json)
  if (err?.type === 'entity.parse.failed') {
    return { status: 400, code: 'INVALID_JSON', message: 'Corpo da requisição não é um JSON válido.' };
  }
  if (err?.type === 'entity.too.large') {
    return { status: 413, code: 'PAYLOAD_TOO_LARGE', message: 'Corpo da requisição excede o limite permitido.' };
  }
  if (err?.type === 'encoding.unsupported' || err?.type === 'charset.unsupported') {
    return { status: 415, code: 'UNSUPPORTED_MEDIA_TYPE', message: 'Codificação não suportada.' };
  }

  // 3.3 JWT (jsonwebtoken) - sem vazar o motivo exato da falha
  if (err?.name === 'TokenExpiredError') {
    return { status: 401, code: 'TOKEN_EXPIRED', message: 'Sessão expirada.', headers: { 'WWW-Authenticate': 'Bearer' } };
  }
  if (err?.name === 'JsonWebTokenError' || err?.name === 'NotBeforeError') {
    return { status: 401, code: 'UNAUTHORIZED', message: 'Autenticação inválida.', headers: { 'WWW-Authenticate': 'Bearer' } };
  }

  // 3.4 Validadores de schema (Zod / Joi): só caminho e mensagem, nunca o valor enviado
  if (err?.name === 'ZodError' && Array.isArray(err.issues)) {
    return {
      status: 422,
      code: 'VALIDATION_ERROR',
      message: 'Dados inválidos.',
      details: err.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
    };
  }
  if (err?.isJoi && Array.isArray(err.details)) {
    return {
      status: 422,
      code: 'VALIDATION_ERROR',
      message: 'Dados inválidos.',
      details: err.details.map((d) => ({ field: d.path.join('.'), message: d.message })),
    };
  }

  // 3.5 PostgreSQL (driver pg): mensagens do banco contêm nomes de tabelas,
  //     constraints e valores, então jamais vão para o cliente.
  switch (err?.code) {
    case '23505': return { status: 409, code: 'DUPLICATE_RESOURCE', message: 'Já existe um registro com estes dados.' };
    case '23503': return { status: 409, code: 'RELATED_RESOURCE_CONFLICT', message: 'Operação conflita com registros relacionados.' };
    case '23502':
    case '23514':
    case '22P02':
    case '22001': return { status: 400, code: 'BAD_REQUEST', message: 'Dados inválidos.' };
    case '40001': // serialization_failure
    case '40P01': // deadlock_detected
    case '57014': // query_canceled (statement_timeout)
    case '53300': // too_many_connections
      return { status: 503, code: 'TEMPORARILY_UNAVAILABLE', message: 'Serviço temporariamente indisponível. Tente novamente.', headers: { 'Retry-After': '2' } };
    default: break;
  }

  // 3.6 Prisma (opcional)
  if (err?.code === 'P2002') return { status: 409, code: 'DUPLICATE_RESOURCE', message: 'Já existe um registro com estes dados.' };
  if (err?.code === 'P2025') return { status: 404, code: 'NOT_FOUND', message: 'Recurso não encontrado.' };

  // 3.7 Erros 4xx de bibliotecas (http-errors, etc.): só o status; mensagem genérica
  const libStatus = err?.status ?? err?.statusCode;
  if (Number.isInteger(libStatus) && libStatus >= 400 && libStatus < 500) {
    return { status: libStatus, code: 'CLIENT_ERROR', message: 'Requisição não pôde ser processada.' };
  }

  // 3.8 Todo o resto: bug ou falha de infraestrutura
  return { ...INTERNAL };
}

/* -------------------------------------------------------------------------- */
/* 4. Logging estruturado (com contexto de tenant, sem dados sensíveis)       */
/* -------------------------------------------------------------------------- */

function serializeError(err) {
  const safe = err instanceof Error ? err : new Error(String(err));
  return {
    name: safe.name,
    message: safe.message,
    code: safe.code,
    stack: safe.stack,
    cause: safe.cause instanceof Error ? { name: safe.cause.name, message: safe.cause.message } : undefined,
  };
}

function logError(req, status, code, err) {
  const entry = {
    level: status >= 500 ? 'error' : 'warn',
    event: 'request_error',
    time: new Date().toISOString(),
    requestId: req.id,
    tenantId: req.auth?.tenantId ?? null,
    userId: req.auth?.userId ?? null,
    method: req.method,
    // originalUrl sem query string (pode carregar tokens/PII); nunca loga body ou headers.
    path: (req.originalUrl || req.url || '').split('?')[0],
    status,
    code,
    // Stack apenas para 5xx; 4xx é ruído esperado do cliente.
    error: status >= 500 ? serializeError(err) : { name: err?.name, message: err?.message },
  };

  const logger = req.log; // ex.: pino/winston, se já estiver acoplado à requisição
  if (logger && typeof logger[entry.level] === 'function') {
    logger[entry.level](entry);
  } else {
    // eslint-disable-next-line no-console
    console[entry.level === 'error' ? 'error' : 'warn'](JSON.stringify(entry));
  }
}

/* -------------------------------------------------------------------------- */
/* 5. Middlewares do Express                                                  */
/* -------------------------------------------------------------------------- */

/** Registrar DEPOIS de todas as rotas, antes do errorHandler. */
function notFoundHandler(req, res, next) {
  next(Errors.notFound('Rota não encontrada.'));
}

/** Assinatura com 4 parâmetros é obrigatória para o Express reconhecer como handler de erro. */
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  // Se a resposta já começou a ser enviada, não dá para trocar status/corpo.
  // Delegar ao handler padrão do Express, que encerra a conexão.
  if (res.headersSent) {
    logError(req, 500, 'HEADERS_ALREADY_SENT', err);
    return next(err);
  }

  let normalized;
  try {
    normalized = normalizeError(err);
    logError(req, normalized.status, normalized.code, err);
  } catch (handlerFailure) {
    // O tratador de erros nunca pode lançar exceção.
    normalized = { ...INTERNAL };
    try {
      // eslint-disable-next-line no-console
      console.error(JSON.stringify({
        level: 'error', event: 'error_handler_failure', requestId: req.id,
        error: serializeError(handlerFailure), original: serializeError(err),
      }));
    } catch { /* nada a fazer */ }
  }

  const { status, code, message, details, headers } = normalized;

  if (headers) {
    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  }
  res.setHeader('Cache-Control', 'no-store');

  const body = {
    error: {
      code,
      message,
      requestId: req.id,
      // details somente em erros 4xx já sanitizados; nunca em 5xx.
      ...(status < 500 && details ? { details } : {}),
    },
  };

  return res.status(status).json(body);
}

/* -------------------------------------------------------------------------- */
/* 6. Rede de segurança no nível do processo                                  */
/* -------------------------------------------------------------------------- */

function registerProcessHandlers(server, { shutdownTimeoutMs = 10_000 } = {}) {
  let shuttingDown = false;

  const fatal = (kind) => (reason) => {
    // eslint-disable-next-line no-console
    console.error(JSON.stringify({
      level: 'fatal', event: kind, time: new Date().toISOString(), error: serializeError(reason),
    }));
    if (shuttingDown) return;
    shuttingDown = true;

    // Estado do processo é incerto: encerra de forma graciosa e deixa o
    // orquestrador (PM2, Kubernetes, etc.) subir uma nova instância.
    const timer = setTimeout(() => process.exit(1), shutdownTimeoutMs);
    timer.unref();
    server.close(() => process.exit(1));
  };

  process.on('unhandledRejection', fatal('unhandled_rejection'));
  process.on('uncaughtException', fatal('uncaught_exception'));
}

/* -------------------------------------------------------------------------- */
/* 7. Exemplo de uso                                                          */
/* -------------------------------------------------------------------------- */
/*
const express = require('express');
const { requestContext, notFoundHandler, errorHandler, registerProcessHandlers, Errors } = require('./errorHandler');

const app = express();
app.use(requestContext);
app.use(express.json({ limit: '1mb' }));

// ... autenticação (preenche req.auth = { tenantId, userId }) e rotas ...

// Express 4: rotas async precisam repassar o erro (try/catch + next(err) ou wrapper).
// Express 5: rejeições de handlers async já chegam ao errorHandler automaticamente.

app.use(notFoundHandler);
app.use(errorHandler);

const server = app.listen(process.env.PORT || 3000);
registerProcessHandlers(server);
*/

module.exports = {
  AppError,
  Errors,
  requestContext,
  notFoundHandler,
  errorHandler,
  normalizeError,
  registerProcessHandlers,
};