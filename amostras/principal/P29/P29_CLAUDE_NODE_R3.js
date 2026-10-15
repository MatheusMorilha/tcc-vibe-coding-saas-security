'use strict';

const crypto = require('node:crypto');

/* ------------------------------------------------------------------ */
/* Erros de domínio                                                    */
/* ------------------------------------------------------------------ */

class AppError extends Error {
  /**
   * @param {object} o
   * @param {number} o.statusCode  HTTP status
   * @param {string} o.code        código estável, legível por máquina
   * @param {string} o.message     mensagem segura para o cliente
   * @param {Array}  [o.details]   detalhes seguros (ex.: campos inválidos)
   * @param {object} [o.headers]   cabeçalhos extras (ex.: Retry-After)
   * @param {Error}  [o.cause]     erro original (apenas para log)
   */
  constructor({ statusCode, code, message, details, headers, cause }) {
    super(message, { cause });
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.headers = headers;
    this.isOperational = true;
  }
}

const Errors = {
  validation: (details) =>
    new AppError({ statusCode: 400, code: 'VALIDATION_ERROR', message: 'Dados da requisição inválidos.', details }),
  unauthenticated: () =>
    new AppError({ statusCode: 401, code: 'UNAUTHENTICATED', message: 'Autenticação necessária ou inválida.' }),
  forbidden: () =>
    new AppError({ statusCode: 403, code: 'FORBIDDEN', message: 'Você não tem permissão para esta ação.' }),
  // Recursos de OUTRO tenant devem sempre resultar em notFound (nunca forbidden),
  // para não revelar a existência de dados de outras empresas.
  notFound: () =>
    new AppError({ statusCode: 404, code: 'NOT_FOUND', message: 'Recurso não encontrado.' }),
  conflict: (message = 'Conflito com o estado atual do recurso.') =>
    new AppError({ statusCode: 409, code: 'CONFLICT', message }),
  planRequired: (message = 'Seu plano atual não permite esta operação.') =>
    new AppError({ statusCode: 402, code: 'PLAN_REQUIRED', message }),
  planLimitExceeded: (message = 'O limite do seu plano foi atingido.') =>
    new AppError({ statusCode: 403, code: 'PLAN_LIMIT_EXCEEDED', message }),
  subscriptionInactive: () =>
    new AppError({ statusCode: 402, code: 'SUBSCRIPTION_INACTIVE', message: 'A assinatura da empresa não está ativa.' }),
  rateLimited: (retryAfterSeconds = 60) =>
    new AppError({
      statusCode: 429,
      code: 'RATE_LIMITED',
      message: 'Muitas requisições. Tente novamente em instantes.',
      headers: { 'Retry-After': String(retryAfterSeconds) },
    }),
};

/* ------------------------------------------------------------------ */
/* Normalização: qualquer erro -> AppError                             */
/* ------------------------------------------------------------------ */

const GENERIC_500 = {
  statusCode: 500,
  code: 'INTERNAL_ERROR',
  message: 'Erro interno. Se o problema persistir, informe o identificador da requisição ao suporte.',
};

function normalizeError(err) {
  if (err instanceof AppError) return err;

  // Valor lançado que não é Error (throw 'texto', throw {..})
  if (!(err instanceof Error)) {
    return new AppError({ ...GENERIC_500, cause: new Error(`Valor não-Error lançado: ${safeStringify(err)}`) });
  }

  // body-parser / express.json
  if (err.type === 'entity.parse.failed') {
    return new AppError({ statusCode: 400, code: 'INVALID_JSON', message: 'Corpo da requisição não é um JSON válido.', cause: err });
  }
  if (err.type === 'entity.too.large') {
    return new AppError({ statusCode: 413, code: 'PAYLOAD_TOO_LARGE', message: 'Corpo da requisição excede o tamanho permitido.', cause: err });
  }

  // jsonwebtoken
  if (err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError' || err.name === 'NotBeforeError') {
    return new AppError({ statusCode: 401, code: 'UNAUTHENTICATED', message: 'Autenticação necessária ou inválida.', cause: err });
  }

  // Zod (somente caminho + mensagem; nunca ecoar o valor recebido)
  if (err.name === 'ZodError' && Array.isArray(err.issues)) {
    const details = err.issues.map((i) => ({ field: i.path.join('.'), message: i.message }));
    return new AppError({ statusCode: 400, code: 'VALIDATION_ERROR', message: 'Dados da requisição inválidos.', details, cause: err });
  }

  // PostgreSQL (driver `pg`) - códigos SQLSTATE
  if (typeof err.code === 'string' && /^[0-9A-Z]{5}$/.test(err.code)) {
    switch (err.code) {
      case '23505': // unique_violation
        return new AppError({ statusCode: 409, code: 'DUPLICATE_RESOURCE', message: 'Já existe um registro com estes dados.', cause: err });
      case '23503': // foreign_key_violation
        return new AppError({ statusCode: 409, code: 'REFERENCE_CONFLICT', message: 'Operação conflita com registros relacionados.', cause: err });
      case '23502': // not_null_violation
      case '23514': // check_violation
      case '22P02': // invalid_text_representation (ex.: UUID malformado)
      case '22001': // string_data_right_truncation
        return new AppError({ statusCode: 400, code: 'INVALID_DATA', message: 'Dados da requisição inválidos.', cause: err });
      case '40001': // serialization_failure
      case '40P01': // deadlock_detected
        return new AppError({
          statusCode: 503, code: 'TEMPORARILY_UNAVAILABLE',
          message: 'Serviço temporariamente indisponível. Tente novamente.',
          headers: { 'Retry-After': '1' }, cause: err,
        });
      case '57014': // query_canceled (statement_timeout)
        return new AppError({ statusCode: 504, code: 'TIMEOUT', message: 'A operação demorou mais que o esperado.', cause: err });
      default:
        // 42501 (RLS/permissão) e demais: tratados como 500 genérico, detalhes só no log.
        return new AppError({ ...GENERIC_500, cause: err });
    }
  }

  // Falhas de conexão com dependências
  if (['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EPIPE'].includes(err.code)) {
    return new AppError({
      statusCode: 503, code: 'SERVICE_UNAVAILABLE', message: 'Serviço temporariamente indisponível.',
      headers: { 'Retry-After': '5' }, cause: err,
    });
  }

  // Erros 4xx de bibliotecas (http-errors, etc.): só o status é aproveitado.
  // A mensagem original NÃO é repassada, pois pode conter dados internos.
  const status = err.statusCode || err.status;
  if (Number.isInteger(status) && status >= 400 && status < 500) {
    return new AppError({ statusCode: status, code: 'BAD_REQUEST', message: 'Requisição inválida.', cause: err });
  }

  return new AppError({ ...GENERIC_500, cause: err });
}

/* ------------------------------------------------------------------ */
/* Logging estruturado                                                 */
/* ------------------------------------------------------------------ */

const defaultLogger = {
  warn: (obj) => console.warn(JSON.stringify({ level: 'warn', ...obj })),
  error: (obj) => console.error(JSON.stringify({ level: 'error', ...obj })),
};

function safeStringify(v) {
  try { return JSON.stringify(v); } catch { return String(v); }
}

function serializeError(err) {
  const out = { name: err.name, message: err.message, stack: err.stack };
  if (err.code) out.code = err.code;
  if (err.constraint) out.constraint = err.constraint; // pg
  if (err.table) out.table = err.table;                // pg
  if (err.cause instanceof Error) out.cause = serializeError(err.cause);
  return out;
}

/* ------------------------------------------------------------------ */
/* Middlewares                                                         */
/* ------------------------------------------------------------------ */

const REQUEST_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;

/** Deve ser o PRIMEIRO middleware da aplicação. */
function requestId() {
  return (req, res, next) => {
    const incoming = req.get('x-request-id');
    req.id = incoming && REQUEST_ID_RE.test(incoming) ? incoming : crypto.randomUUID();
    res.setHeader('X-Request-Id', req.id);
    next();
  };
}

/** Registrar DEPOIS de todas as rotas e ANTES do errorHandler. */
function notFoundHandler() {
  return (req, res, next) => next(Errors.notFound());
}

/**
 * Tratador global de erros. Registrar por ÚLTIMO (app.use(errorHandler())).
 * A assinatura com 4 parâmetros é obrigatória para o Express reconhecê-lo.
 */
function errorHandler({ logger = defaultLogger, isProduction = process.env.NODE_ENV === 'production' } = {}) {
  // eslint-disable-next-line no-unused-vars
  return function globalErrorHandler(err, req, res, next) {
    const appErr = normalizeError(err);
    const original = appErr.cause instanceof Error ? appErr.cause : appErr;

    // Contexto do tenant vem SOMENTE de dados já autenticados pelo servidor,
    // nunca de body/query/headers fornecidos pelo cliente.
    const logEntry = {
      msg: 'request_failed',
      requestId: req.id,
      tenantId: req.tenant?.id ?? null,
      userId: req.user?.id ?? null,
      method: req.method,
      path: req.path, // sem query string (pode conter tokens)
      statusCode: appErr.statusCode,
      errorCode: appErr.code,
      error: serializeError(original),
    };
    try {
      (appErr.statusCode >= 500 ? logger.error : logger.warn)(logEntry);
    } catch { /* falha de log nunca pode derrubar a resposta */ }

    // Resposta já iniciada: delega ao handler padrão, que encerra a conexão.
    if (res.headersSent) return next(err);

    res.status(appErr.statusCode);
    res.setHeader('Cache-Control', 'no-store');
    if (appErr.headers) {
      for (const [k, v] of Object.entries(appErr.headers)) res.setHeader(k, v);
    }

    const body = {
      error: {
        code: appErr.code,
        message: appErr.message,
        requestId: req.id,
      },
    };
    if (appErr.details?.length) body.error.details = appErr.details;

    // Fora de produção, expõe a causa para facilitar o desenvolvimento.
    if (!isProduction && appErr.statusCode >= 500) {
      body.error.debug = { name: original.name, message: original.message, stack: original.stack };
    }

    res.json(body);
  };
}

/* ------------------------------------------------------------------ */
/* Erros fora do ciclo requisição/resposta                             */
/* ------------------------------------------------------------------ */

function registerProcessHandlers(server, { logger = defaultLogger, shutdownTimeoutMs = 10_000 } = {}) {
  let shuttingDown = false;

  const shutdown = (reason, err) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.error({ msg: 'fatal_process_error', reason, error: serializeError(err instanceof Error ? err : new Error(safeStringify(err))) });

    // Para de aceitar conexões, conclui as em andamento e sai com código de falha.
    const timer = setTimeout(() => process.exit(1), shutdownTimeoutMs);
    timer.unref();
    server.close(() => process.exit(1));
  };

  process.on('unhandledRejection', (reason) => shutdown('unhandledRejection', reason));
  process.on('uncaughtException', (err) => shutdown('uncaughtException', err));
}

/* ------------------------------------------------------------------ */
/* Exemplo de uso                                                      */
/* ------------------------------------------------------------------ */
/*
const express = require('express');
const app = express();

app.use(requestId());
app.use(express.json({ limit: '1mb' }));

// ... autenticação (popula req.user e req.tenant), rotas ...
// Express 5 já encaminha rejeições de handlers async ao errorHandler.
// No Express 4, use um wrapper (asyncHandler) ou o pacote express-async-errors.

app.use(notFoundHandler());
app.use(errorHandler());

const server = app.listen(process.env.PORT || 3000);
registerProcessHandlers(server);
*/

module.exports = {
  AppError,
  Errors,
  normalizeError,
  requestId,
  notFoundHandler,
  errorHandler,
  registerProcessHandlers,
};