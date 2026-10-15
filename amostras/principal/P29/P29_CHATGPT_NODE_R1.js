'use strict';

function globalErrorHandler(err, req, res, next) {
  const statusCode =
    Number.isInteger(err.statusCode)&& err.statusCode>= 400 && err.statusCode< 600
      ? err.statusCode
      : 500;

  const isProduction = process.env.NODE_ENV === 'production';

  // Log interno: nunca enviar stack trace ou detalhes sensíveis ao cliente.
  console.error({
    message: err.message,
    stack: err.stack,
    method: req.method,
    path: req.originalUrl|| req.url,
    tenantId: req.tenantId|| null
  });

  const response = {
    error: {
      status: statusCode,
      message:
        statusCode>= 500 && isProduction
          ? 'Ocorreu um erro interno no servidor.'
          : err.message|| 'Erro ao processar a requisição.'
    }
  };

  // Em desenvolvimento, facilita diagnóstico sem expor isso em produção.
  if (!isProduction&& err.stack) {
    response.error.stack= err.stack;
  }

  res.status(statusCode).json(response);
}

module.exports = globalErrorHandler;

const globalErrorHandler = require('./middlewares/globalErrorHandler');

app.use(globalErrorHandler);