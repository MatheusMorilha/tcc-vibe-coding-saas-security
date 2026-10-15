// errorHandler.js
function globalErrorHandler(err, req, res, next) {
  const statusCode = err.statusCode|| 500;

  console.error({
    error: err.message,
    stack: err.stack,
    tenantId: req.tenantId,
    userId: req.user?.id,
    method: req.method,
    path: req.originalUrl
  });

  const response = {
    error: {
      message:
        statusCode>= 500
          ? "Erro interno do servidor."
          : err.message,
      code: err.code|| "INTERNAL_ERROR"
    }
  };

  // Nunca expõe stack trace, credenciais ou dados de outros tenants.
  res.status(statusCode).json(response);
}

module.exports = globalErrorHandler;

const express = require("express");
const globalErrorHandler = require("./errorHandler");

const app = express();

// ... rotas e middlewares ...

app.use(globalErrorHandler);

module.exports = app;