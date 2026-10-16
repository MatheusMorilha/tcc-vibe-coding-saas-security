'use strict';

/**
 * Middleware de auditoria para tentativas de autenticação malsucedidas.
 *
 * Requisitos:
 * - Node.js
 * - Express
 *
 * Princípios de segurança:
 * - Nunca registra senha, token, cookie ou Authorization.
 * - Não registra req.body inteiro.
 * - Usa allowlist para definir quais campos podem aparecer no log.
 * - Limita tamanho dos valores registrados.
 * - Gera um requestId para correlação.
 * - Não confia em tenantId enviado pelo cliente.
 * - Evita registrar dados sensíveis em URLs.
 *
 * IMPORTANTE:
 * Este middleware deve ser executado APENAS quando a autenticação falhar.
 */

const crypto = require('node:crypto');

const DEFAULT_ALLOWED_FIELDS = [
  'email',
  'username',
  'login'
];

const SENSITIVE_FIELD_PATTERN =
  /password|passwd|pwd|token|secret|authorization|cookie|session|api[-_]?key|access[-_]?token|refresh[-_]?token|client[-_]?secret|otp|code/i;

const MAX_VALUE_LENGTH = 256;

function generateRequestId() {
  return crypto.randomUUID();
}

function sanitizeValue(value) {
  if (value=== null || value=== undefined) {
    return null;
  }

  if (typeof value=== 'string') {
    return value.length > MAX_VALUE_LENGTH
      ? `${value.slice(0, MAX_VALUE_LENGTH)}...[truncated]`
      : value;
  }

  if (
    typeof value=== 'number' ||
    typeof value=== 'boolean'
  ) {
    return value;
  }

  // Objetos e arrays não são necessários para a auditoria
  // e podem conter segredos inesperados.
  return '[omitted]';
}

function getSafeRequestData(body, allowedFields) {
  if (!body|| typeof body!== 'object') {
    return {};
  }

  const result = {};

  for (const field of allowedFields) {
    if (!Object.prototype.hasOwnProperty.call(body, field)) {
      continue;
    }

    // Defesa adicional mesmo que alguém inclua acidentalmente
    // um campo sensível na configuração.
    if (SENSITIVE_FIELD_PATTERN.test(field)) {
      continue;
    }

    result[field]= sanitizeValue(body[field]);
  }

  return result;
}

/**
 * Registra uma tentativa de autenticação malsucedida.
 *
 *@param {Object} options
 *@param {string[]} [options.allowedFields]
 *@param {Object} [options.logger]
 */
function failedAuthenticationLogger(options= {}) {
  const allowedFields =
    Array.isArray(options.allowedFields)
      ? options.allowedFields
      : DEFAULT_ALLOWED_FIELDS;

  const logger = options.logger|| console;

  return function failedAuthenticationAudit(req, res, next) {
    /*
     * O middleware assume que a camada de autenticação definiu
     * req.authFailure quando a tentativa falhou.
     *
     * Exemplo:
     *
     * req.authFailure = {
     *   reason: 'invalid_credentials'
     * };
     */
    if (!req.authFailure) {
      return next();
    }

    const requestId =
      req.id||
      req.requestId||
      generateRequestId();

    /*
     * O tenantId NÃO deve ser obtido de req.body, query string
     * ou qualquer valor fornecido pelo cliente.
     *
     * Se existir, deve ter sido determinado previamente por uma
     * camada confiável da aplicação.
     */
    const tenantId =
      req.tenant?.id||
      req.auth?.tenantId||
      null;

    const logEntry = {
      event: 'authentication_failure',
      timestamp: new Date().toISOString(),
      requestId,

      // Identificação técnica da requisição
      method: req.method,
      route: req.route?.path|| req.path,

      // Dados de rede úteis para investigação.
      // Em ambientes com proxy reverso, req.ip deve ser configurado
      // adequadamente através de "trust proxy".
      ip: req.ip|| null,
      userAgent: sanitizeValue(req.get('user-agent')),

      // Contexto multilocatário, quando conhecido de fonte confiável.
      tenantId,

      // Motivo categórico, sem registrar detalhes de autenticação.
      reason:
        typeof req.authFailure.reason=== 'string'
          ? req.authFailure.reason
          : 'authentication_failed',

      /*
       * Somente campos explicitamente permitidos.
       *
       * NUNCA:
       * - req.body inteiro
       * - Authorization header
       * - Cookie
       * - password
       * - tokens
       */
      submittedFields: getSafeRequestData(
        req.body,
        allowedFields
      )
    };

    /*
     * O logger deve escrever JSON estruturado para permitir
     * pesquisa posterior no sistema de observabilidade.
     */
    logger.warn(
      JSON.stringify(logEntry)
    );

    return next();
  };
}

module.exports = {
  failedAuthenticationLogger
};

'use strict';

const express = require('express');
const {
  failedAuthenticationLogger
}= require('./failed-authentication-logger');

const app = express();

app.use(express.json({ limit: '32kb' }));

app.post('/auth/login', async (req, res, next)=> {
  try {
    const {email, password }= req.body;

    const user = await authenticateUser(email, password);

    if (!user) {
      req.authFailure= {
        reason: 'invalid_credentials'
      };

      return next();
    }

    // Contexto confiável somente após autenticação bem-sucedida.
    req.auth= {
      userId: user.id,
      tenantId: user.tenantId
    };

    return res.status(200).json({
      authenticated: true
    });
  }catch (error) {
    return next(error);
  }
});

app.use(
  failedAuthenticationLogger({
    allowedFields: [
      'email',
      'username',
      'login'
    ]
  })
);

/*
 * Handler específico para falha de autenticação.
 */
app.use((req, res, next)=> {
  if (req.authFailure) {
    return res.status(401).json({
      error: 'invalid_credentials'
    });
  }

  return next();
});