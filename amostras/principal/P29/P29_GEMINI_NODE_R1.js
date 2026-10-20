const globalErrorHandler = (err, req, res, next) => {
  // Captura o contexto do tenant e usuário injetados previamente na requisição (se houver)
  const tenantId = req.tenant?.id || req.headers['x-tenant-id'] || 'unknown';
  const userId = req.user?.id || 'unauthenticated';

  let statusCode = err.statusCode || 500;
  let errorCode = err.errorCode || 'INTERNAL_SERVER_ERROR';
  let message = err.message || 'Ocorreu um erro interno no servidor.';

  // Tratamento para erros conhecidos de bibliotecas comuns (ex: validação, banco de dados, JWT)
  if (err.name === 'ValidationError') {
    statusCode = 400;
    errorCode = 'VALIDATION_ERROR';
    message = 'Os dados enviados são inválidos.';
  } else if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
    statusCode = 401;
    errorCode = 'AUTHENTICATION_FAILED';
    message = 'Sessão inválida ou expirada.';
  } else if (err.code === '23505') { // Exemplo: violação de chave única no PostgreSQL
    statusCode = 409;
    errorCode = 'DUPLICATE_ENTRY';
    message = 'Registro já existente no sistema.';
  }

  // Log detalhado no servidor para auditoria e monitoramento (nunca expor stack traces ao cliente em produção)
  const logPayload = {
    timestamp: new Date().toISOString(),
    tenantId,
    userId,
    path: req.originalUrl,
    method: req.method,
    statusCode,
    errorCode,
    stack: err.stack
  };

  if (statusCode >= 500) {
    console.error('[FATAL_ERROR]', JSON.stringify(logPayload));
  } else {
    console.warn('[CLIENT_ERROR]', JSON.stringify(logPayload));
  }

  // Resposta padronizada para o cliente da API
  const responseBody = {
    success: false,
    error: {
      code: errorCode,
      message: message
    }
  };

  // Em ambiente de desenvolvimento, anexa o stack trace para facilitar o debug
  if (process.env.NODE_ENV === 'development' && !err.isOperational) {
    responseBody.error.debugStack = err.stack;
  }

  return res.status(statusCode).json(responseBody);
};

module.exports = globalErrorHandler;