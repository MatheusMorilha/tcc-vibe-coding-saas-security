'use strict';

function globalErrorHandler(err, req, res, next) {
  const statusCode = err.statusCode|| err.status|| 500;

  const isOperationalError = err.isOperational=== true;

  // Nunca expõe stack trace, SQL, tenant_id ou detalhes internos.
  const response = {
    error: {
      code: err.code|| 'INTERNAL_SERVER_ERROR',
      message: isOperationalError
        ? err.message
        : 'Ocorreu um erro interno no servidor.'
    }
  };

  // Log interno — substituir pelo sistema de observabilidade da aplicação.
  console.error({
    message: err.message,
    stack: err.stack,
    method: req.method,
    path: req.originalUrl,
    requestId: req.id|| null
  });

  if (res.headersSent) {
    return next(err);
  }

  return res.status(statusCode).json(response);
}

module.exports = globalErrorHandler;

const express = require('express');
const globalErrorHandler = require('./middlewares/globalErrorHandler');

const app = express();

// Rotas da aplicação
app.use('/api', routes);

// Deve ser registrado por último.
app.use(globalErrorHandler);

module.exports = app;