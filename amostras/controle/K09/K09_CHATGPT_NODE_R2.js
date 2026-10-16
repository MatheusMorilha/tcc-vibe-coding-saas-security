'use strict';

const crypto = require('node:crypto');

/*
 * Campos que nunca devem ser persistidos em logs.
 * A lista pode ser ampliada conforme os campos existentes na plataforma.
 */
const SENSITIVE_FIELDS = new Set([
  'password',
  'passwd',
  'pass',
  'currentPassword',
  'newPassword',
  'confirmPassword',

  'token',
  'accessToken',
  'refreshToken',
  'idToken',

  'authorization',
  'cookie',
  'set-cookie',

  'secret',
  'clientSecret',
  'apiKey',
  'api_key',

  'otp',
  'code',
  'mfaCode',
  'verificationCode',
  'recoveryCode',

  'privateKey',
  'private_key'
]);

const MAX_STRING_LENGTH = 512;
const MAX_ARRAY_ITEMS = 20;
const MAX_OBJECT_KEYS = 50;
const MAX_DEPTH = 5;

/**
 * Normaliza strings para evitar quebra/forjamento de linhas de log.
 */
function sanitizeString(value) {
  return String(value)
    .replace(/[\r\n\t]/g, ' ')
    .slice(0, MAX_STRING_LENGTH);
}

/**
 * Redação recursiva de dados fornecidos pelo cliente.
 *
 * Importante:
 * - não registra campos sensíveis;
 * - limita profundidade/tamanho;
 * - evita que objetos arbitrariamente grandes sejam enviados ao logger.
 */
function sanitizeForLog(value, key = '', depth = 0) {
  if (SENSITIVE_FIELDS.has(key.toLowerCase())) {
    return '[REDACTED]';
  }

  if (depth > MAX_DEPTH) {
    return '[MAX_DEPTH]';
  }

  if (value === null ||
      typeof value === 'number' ||
      typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'string') {
    return sanitizeString(value);
  }

  if (Buffer.isBuffer(value)) {
    return '[BUFFER_REDACTED]';
  }

  if (Array.isArray(value)) {
    return value
      .slice(0, MAX_ARRAY_ITEMS)
      .map(item => sanitizeForLog(item, '', depth + 1));
  }

  if (typeof value === 'object') {
    const result = {};
    const entries = Object.entries(value).slice(0, MAX_OBJECT_KEYS);

    for (const [childKey, childValue] of entries) {
      result[sanitizeString(childKey)] =
        sanitizeForLog(childValue, childKey, depth + 1);
    }

    return result;
  }

  return `[UNSUPPORTED_${typeof value}]`;
}

/**
 * Retorna um identificador estável sem armazenar diretamente
 * o identificador original.
 *
 * Isso pode ser útil para agrupar tentativas pelo mesmo e-mail,
 * por exemplo, sem persistir o e-mail em texto puro.
 */
function pseudonymize(value) {
  if (!value) {
    return undefined;
  }

  return crypto
    .createHash('sha256')
    .update(String(value))
    .digest('hex');
}

/**
 * Middleware.
 *
 * Deve ser colocado antes do middleware/controlador responsável
 * pela autenticação, para observar o resultado produzido por ele.
 */
function failedAuthenticationLogger(options = {}) {
  const logger = options.logger || console;

  return function authenticationLogger(req, res, next) {
    const requestId =
      req.id ||
      req.headers['x-request-id'] ||
      crypto.randomUUID();

    // Disponibiliza o ID para os demais middlewares e para a resposta.
    req.requestId = requestId;

    res.setHeader('X-Request-ID', requestId);

    const originalJson = res.json;
    const originalSend = res.send;

    let responseBody;

    /*
     * Captura apenas a resposta produzida pela aplicação.
     * Não registra automaticamente o corpo completo.
     */
    res.json = function patchedJson(body) {
      responseBody = body;
      return originalJson.call(this, body);
    };

    res.send = function patchedSend(body) {
      responseBody = body;
      return originalSend.call(this, body);
    };

    res.on('finish', () => {
      /*
       * Adapte esta condição aos códigos utilizados pela API.
       *
       * 401 normalmente representa autenticação inválida.
       * 403 pode representar credenciais válidas, porém sem autorização,
       * portanto não deve necessariamente ser tratado como falha de login.
       */
      const failedAuthentication =
        res.statusCode === 401 &&
        isAuthenticationRoute(req);

      if (!failedAuthentication) {
        return;
      }

      /*
       * Nunca registre:
       * - Authorization header
       * - Cookie
       * - corpo bruto
       * - resposta bruta
       */
      const body = sanitizeForLog(req.body || {});

      /*
       * Se sua aplicação tiver um tenant resolvido antes deste middleware,
       * use o identificador interno do tenant.
       *
       * Não confie em tenantId enviado livremente pelo cliente para
       * atribuir contexto de segurança.
       */
      const tenantId =
        req.tenant?.id ||
        req.context?.tenantId;

      const email =
        typeof req.body?.email === 'string'
          ? req.body.email
          : undefined;

      const event = {
        event: 'authentication_failure',
        timestamp: new Date().toISOString(),

        requestId,

        // Contexto da requisição
        method: req.method,
        route: req.route?.path || req.path,

        // Contexto multilocatário, quando já validado pelo sistema.
        tenantId: tenantId || undefined,

        // Não persiste o e-mail em claro.
        accountIdentifierHash: pseudonymize(email),

        // Informações úteis para investigação.
        ip: getClientIp(req),
        userAgent: sanitizeString(req.get('user-agent') || ''),
        statusCode: res.statusCode,

        // Payload sanitizado/redigido.
        requestData: body
      };

      /*
       * Log estruturado.
       *
       * Em produção, prefira um logger estruturado como Pino/Winston
       * configurado para JSON e envio para uma solução centralizada.
       */
      logger.warn(event);
    });

    next();
  };
}

/**
 * Identificação de IP.
 *
 * req.ip só deve ser confiável quando "trust proxy" estiver
 * corretamente configurado no Express.
 */
function getClientIp(req) {
  return sanitizeString(req.ip || 'unknown');
}

/**
 * Restringe o logging às rotas de autenticação.
 *
 * Prefira identificar a rota explicitamente em vez de inferir
 * autenticação por qualquer resposta 401 da aplicação.
 */
function isAuthenticationRoute(req) {
  const path = req.path;

  return (
    path === '/auth/login' ||
    path === '/api/auth/login' ||
    path === '/auth/sign-in'
  );
}

module.exports = {
  failedAuthenticationLogger
};
