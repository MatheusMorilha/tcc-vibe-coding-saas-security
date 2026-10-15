'use strict';

const { randomUUID } = require('node:crypto');

/* -------------------------------------------------------------------------- */
/* Erros de domínio                                                           */
/* -------------------------------------------------------------------------- */

/**
 * Erro operacional: previsto pela aplicação e SEGURO para exibir ao cliente.
 * Tudo que não for AppError é tratado como não confiável (mensagem oculta).
 */
class AppError extends Error {
  constructor(message, { statusCode = 500, code = 'INTERNAL_ERROR', details, headers, cause } = {}) {
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
    new AppError(msg, { statusCode: 400, code: 'BAD_REQUEST', details }),
  unauthorized: (msg = 'Autenticação necessária.') =>
    new AppError(msg, { statusCode: 401, code: 'UNAUTHORIZED' }),
  forbidden: (msg = 'Você não tem permissão para esta ação.') =>
    new AppError(msg, { statusCode: 403, code: 'FORBIDDEN' }),
  // Também use 404 para recurso de OUTRO tenant: nunca confirme que ele existe.
  notFound: (msg = 'Recurso não encontrado.') =>
    new AppError(msg, { statusCode: 404, code: 'NOT_FOUND' }),
  conflict: (msg = 'Conflito com o estado atual do recurso.') =>
    new AppError(msg, { statusCode: 409, code: 'CONFLICT' }),
  validation: (details) =>
    new AppError('Dados inválidos.', { statusCode: 422, code: 'VALIDATION_ERROR', details }),
  planRestriction: (msg = 'Seu plano atual não permite esta operação.', details) =>
    new AppError(msg, { statusCode: 402, code: 'PLAN_RESTRICTION', details }),
  planLimit: (msg = 'Limite do plano atingido.', details) =>
    new AppError(msg, { statusCode: 403, code: 'PLAN_LIMIT_REACHED', details }),
  tooManyRequests: (retryAfterSeconds = 60) =>
    new AppError('Muitas requisições. Tente novamente em instantes.', {
      statusCode: 429,
      code: 'RATE_LIMITED',
      headers: { 'Retry-After': String(retryAfterSeconds) },
    }),
};

/* -------------------------------------------------------------------------- */
/* Utilitários                                                                */
/* -------------------------------------------------------------------------- */

const GENERIC_MESSAGES = {
  400: 'Requisição inválida.',
  401: 'Autenticação necessária.',
  403: 'Acesso negado.',
  404: 'Recurso não encontrado.',
  405: 'Método não permitido.',
  409: 'Conflito com o estado atual do recurso.',
  413: 'Corpo da requisição muito grande.',
  415: 'Tipo de conteúdo não suportado.',
  422: 'Dados inválidos.',
  429: 'Muitas requisições. Tente novamente em instantes.',
  500: 'Erro interno. Tente novamente mais tarde.',
  502: 'Serviço temporariamente indisponível.',
  503: 'Serviço temporariamente indisponível.',
  504: 'Tempo de resposta excedido.',
};

const genericMessage = (status) =>
  GENERIC_MESSAGES[status] || (status >= 500 ? GENERIC_MESSAGES[500] : GENERIC_MESSAGES[400]);

const REQUEST_ID_RE = /^[A-Za-z0-9._-]{8,64}$/;

/** Middleware: garante um requestId (valida o recebido para evitar log injection). */
function requestId() {
  return (req, res, next) => {
    const incoming = req.get('x-request-id');
    req.id = incoming && REQUEST_ID_RE.test(incoming) ? incoming : randomUUID();
    res.setHeader('X-Request-Id', req.id);
    next();
  };
}

/** Só para Express 4. No Express 5 rejeições de handlers async já chegam ao tratador. */
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/** Rota 404 - registrar DEPOIS de todas as rotas e ANTES do errorHandler. */
const notFoundHandler = () => (req, res, next) =>
  next(new AppError('Rota não encontrada.', { statusCode: 404, code: 'ROUTE_NOT_FOUND' }));

/* -------------------------------------------------------------------------- */
/* Normalização: qualquer erro -> { status, code, message, details, headers } */
/* -------------------------------------------------------------------------- */

function normalizeError(err) {
  // 1) Erros de domínio: confiáveis.
  if (err instanceof AppError) {
    return {
      status: err.statusCode,
      code: err.code,
      message: err.message,
      details: err.details,
      headers: err.headers,
      operational: true,
    };
  }

  // 2) JSON malformado (body-parser / express.json).
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return { status: 400, code: 'INVALID_JSON', message: 'Corpo da requisição não é um JSON válido.', operational: true };
  }

  // 3) Payload grande / codificação (body-parser, raw-body).
  if (err?.type === 'entity.too.large') {
    return { status: 413, code: 'PAYLOAD_TOO_LARGE', message: genericMessage(413), operational: true };
  }
  if (err?.type === 'charset.unsupported' || err?.type === 'encoding.unsupported') {
    return { status: 415, code: 'UNSUPPORTED_MEDIA_TYPE', message: genericMessage(415), operational: true };
  }

  // 4) JWT (jsonwebtoken).
  if (err?.name === 'TokenExpiredError') {
    return { status: 401, code: 'TOKEN_EXPIRED', message: 'Sessão expirada.', operational: true };
  }
  if (err?.name === 'JsonWebTokenError' || err?.name === 'NotBeforeError') {
    return { status: 401, code: 'INVALID_TOKEN', message: 'Token inválido.', operational: true };
  }

  // 5) Validação (Zod). Expõe apenas caminho + mensagem, nunca o valor enviado.
  if (err?.name === 'ZodError' && Array.isArray(err.issues)) {
    return {
      status: 422,
      code: 'VALIDATION_ERROR',
      message: 'Dados inválidos.',
      details: err.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
      operational: true,
    };
  }

  // 6) Erros do PostgreSQL (driver `pg`). NUNCA repasse err.detail/constraint/table:
  //    em base compartilhada, "Key (email)=(x) already exists" revelaria dados de outros tenants.
  if (typeof err?.code === 'string' && /^[0-9A-Z]{5}$/.test(err.code) && ('severity' in err || 'routine' in err)) {
    switch (err.code) {
      case '23505': return { status: 409, code: 'CONFLICT', message: 'Já existe um registro com estes dados.', operational: true };
      case '23503': return { status: 409, code: 'REFERENCE_CONFLICT', message: 'Operação conflita com registros relacionados.', operational: true };
      case '23502':
      case '23514':
      case '22P02':
      case '22001':
      case '22003': return { status: 400, code: 'INVALID_DATA', message: 'Dados inválidos.', operational: true };
      case '40001':
      case '40P01': return { status: 503, code: 'TRY_AGAIN', message: 'Conflito temporário. Tente novamente.', headers: { 'Retry-After': '1' }, operational: true };
      case '57014': return { status: 504, code: 'TIMEOUT', message: genericMessage(504), operational: true };
      case '42501': // RLS / permissão negada no banco: trate como falha interna, não revele a política.
        return { status: 500, code: 'INTERNAL_ERROR', message: genericMessage(500), operational: false };
      default:
        if (err.code.startsWith('08') || err.code.startsWith('53') || err.code === '57P01') {
          return { status: 503, code: 'SERVICE_UNAVAILABLE', message: genericMessage(503), headers: { 'Retry-After': '5' }, operational: false };
        }
        return { status: 500, code: 'INTERNAL_ERROR', message: genericMessage(500), operational: false };
    }
  }

  // 7) Erros HTTP de bibliotecas (http-errors, express-rate-limit etc.).
  const status = Number(err?.statusCode ?? err?.status);
  if (Number.isInteger(status) && status >= 400 && status <= 599) {
    const is4xx = status < 500;
    return {
      status,
      code: is4xx ? err.code && /^[A-Z_]+$/.test(err.code) ? err.code : 'CLIENT_ERROR' : 'INTERNAL_ERROR',
      // Em 4xx, só usa a mensagem se a lib marcou como segura (err.expose === true).
      message: is4xx && err.expose === true && typeof err.message === 'string' ? err.message : genericMessage(status),
      operational: is4xx,
    };
  }

  // 8) Qualquer outra coisa (bug, TypeError, erro de lib desconhecida): 500 opaco.
  return { status: 500, code: 'INTERNAL_ERROR', message: genericMessage(500), operational: false };
}

/* -------------------------------------------------------------------------- */
/* Logging estruturado (sem body, headers, query string ou tokens)            */
/* -------------------------------------------------------------------------- */

const defaultLogger = {
  warn: (obj) => console.warn(JSON.stringify(obj)),
  error: (obj) => console.error(JSON.stringify(obj)),
};

function serializeCause(err) {
  return {
    name: err?.name,
    message: err?.message,
    code: err?.code, // código do driver/lib, útil para diagnóstico
    stack: err?.stack,
  };
}

/* -------------------------------------------------------------------------- */
/* Tratador global                                                            */
/* -------------------------------------------------------------------------- */

/**
 * @param {object} [opts]
 * @param {{warn:Function,error:Function}} [opts.logger]  pino/winston compatível
 * @param {boolean} [opts.exposeStack=false] Inclui stack na resposta (apenas desenvolvimento)
 */
function errorHandler({ logger = defaultLogger, exposeStack = process.env.NODE_ENV === 'development' } = {}) {
  // A assinatura com 4 parâmetros é obrigatória para o Express reconhecer o middleware de erro.
  // eslint-disable-next-line no-unused-vars
  return function globalErrorHandler(err, req, res, next) {
    const normalized = normalizeError(err);
    const { status, code, message, details, headers } = normalized;
    const reqId = req.id || randomUUID();

    // --- Log: contexto de tenant é essencial para suporte e auditoria ---
    const entry = {
      level: status >= 500 ? 'error' : 'warn',
      msg: 'request_failed',
      requestId: reqId,
      tenantId: req.tenant?.id ?? req.auth?.tenantId ?? null,
      userId: req.user?.id ?? req.auth?.userId ?? null,
      method: req.method,
      path: req.path, // sem query string (pode conter tokens/PII)
      status,
      code,
      operational: normalized.operational,
    };
    if (status >= 500 || !normalized.operational) entry.err = serializeCause(err);
    try {
      (status >= 500 ? logger.error : logger.warn).call(logger, entry);
    } catch {
      /* falha de log jamais pode derrubar a resposta */
    }

    // --- Resposta já iniciada: não dá para enviar JSON. Delegue ao Express (fecha a conexão). ---
    if (res.headersSent) return next(err);

    if (headers) for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    res.setHeader('X-Request-Id', reqId);
    res.setHeader('Cache-Control', 'no-store');

    const body = { error: { code, message, requestId: reqId } };
    if (details !== undefined) body.error.details = details;
    if (exposeStack && status >= 500) body.error.stack = err?.stack;

    return res.status(status).json(body);
  };
}

/* -------------------------------------------------------------------------- */
/* Rede de segurança no nível do processo                                     */
/* -------------------------------------------------------------------------- */

/**
 * Após uncaughtException o estado do processo é indefinido: registre, encerre
 * as conexões de forma ordenada e deixe o orquestrador (PM2/K8s) reiniciar.
 */
function registerProcessHandlers({ server, logger = defaultLogger, shutdownTimeoutMs = 10_000 } = {}) {
  let shuttingDown = false;

  const shutdown = (reason, err) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.error({ level: 'fatal', msg: reason, err: serializeCause(err) });

    const force = setTimeout(() => process.exit(1), shutdownTimeoutMs);
    force.unref();

    if (server) server.close(() => process.exit(1));
    else process.exit(1);
  };

  process.on('uncaughtException', (err) => shutdown('uncaught_exception', err));
  process.on('unhandledRejection', (reason) =>
    shutdown('unhandled_rejection', reason instanceof Error ? reason : new Error(String(reason)))
  );
}

module.exports = {
  AppError,
  Errors,
  requestId,
  asyncHandler,
  notFoundHandler,
  errorHandler,
  registerProcessHandlers,
  normalizeError, // exportado para testes unitários
};

/* -------------------------------------------------------------------------- */
/* Exemplo de uso                                                             */
/* -------------------------------------------------------------------------- */
/*
const express = require('express');
const { requestId, notFoundHandler, errorHandler, registerProcessHandlers, Errors } = require('./errorHandler');

const app = express();
app.use(requestId());
app.use(express.json({ limit: '1mb' }));

// ... auth/tenant middleware preenche req.auth = { tenantId, userId } ...

app.get('/invoices/:id', async (req, res) => {
  const invoice = await repo.findById(req.auth.tenantId, req.params.id); // sempre filtra por tenant
  if (!invoice) throw Errors.notFound('Fatura não encontrada.');         // 404 também para outro tenant
  res.json(invoice);
});

app.use(notFoundHandler());
app.use(errorHandler());           // SEMPRE o último middleware

const server = app.listen(3000);
registerProcessHandlers({ server });
*/