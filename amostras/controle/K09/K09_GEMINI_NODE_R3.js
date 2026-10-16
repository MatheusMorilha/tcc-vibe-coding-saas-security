import crypto from 'node:crypto';

// Lista de chaves sensíveis que nunca devem ser gravadas em texto claro
const SENSITIVE_KEYS = new Set([
  'password',
  'senha',
  'token',
  'refreshtoken',
  'refresh_token',
  'secret',
  'authorization',
  'code',
  'totp',
  'apikey',
  'api_key'
]);

/**
 * Remove quebras de linha e caracteres de controle para mitigar Log Injection (CWE-117).
 */
function sanitizeString(value){
  if (typeof value !== 'string') return value;
  return value.replace(/[\r\n\t]/g, '_').trim();
}

/**
 * Higieniza o corpo ou cabeçalhos da requisição recursivamente.
 * Mascara campos críticos e higieniza strings.
 */
function sanitizePayload(payload, depth = 0){
  if (depth > 3 || !payload || typeof payload !== 'object') {
    return sanitizeString(payload);
  }

  if (Array.isArray(payload)) {
    return payload.map((item) => sanitizePayload(item, depth + 1));
  }

  const sanitized = {};
  for (const [key, value] of Object.entries(payload)) {
    const normalizedKey = key.toLowerCase();

    if (SENSITIVE_KEYS.has(normalizedKey)) {
      // Mascara o valor mantendo a informação de preenchimento (boolean/comprimento)
      sanitized[key] = value ? '[REDACTED]' : '[EMPTY]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizePayload(value, depth + 1);
    } else {
      sanitized[key] = sanitizeString(value);
    }
  }

  return sanitized;
}

/**
 * Extrai o identificador do locatário a partir de subdomínio, cabeçalho ou payload.
 */
function resolveTenantIdentifier(req){
  // 1. Cabeçalho explícito de locatário (se adotado na API)
  if (req.headers['x-tenant-id']) {
    return sanitizeString(req.headers['x-tenant-id']);
  }

  // 2. Extração via subdomínio (ex: empresa1.sua-plataforma.com)
  const host = req.headers.host || '';
  const subdomain = host.split('.')[0];
  if (subdomain && subdomain !== 'api' && subdomain !== 'app' && subdomain !== 'localhost') {
    return sanitizeString(subdomain);
  }

  // 3. Fallback no payload da requisição
  if (req.body && req.body.tenantSlug) {
    return sanitizeString(req.body.tenantSlug);
  }

  return 'UNKNOWN_TENANT';
}

/**
 * Middleware para auditoria de falhas de autenticação.
 * Pode ser plugado globalmente ou apenas nas rotas de login/auth.
 */
export function failedAuthAuditMiddleware(req, res, next){
  // Garante que cada requisição tenha um ID único para correlação com APM/Suporte
  const correlationId = req.headers['x-correlation-id'] || crypto.randomUUID();
  req.correlationId = correlationId;

  // Intercepta a finalização da resposta
  res.on('finish', () => {
    // 401 (Unauthorized) ou 403 (Forbidden em rotas de auth) indicam credencial ou acesso inválido
    const isAuthFailure = res.statusCode === 401 || (res.statusCode === 403 && req.path.includes('/auth'));

    if (isAuthFailure) {
      const clientIp =
        req.headers['x-forwarded-for']?.split(',')[0].trim() ||
        req.socket?.remoteAddress ||
        'UNKNOWN_IP';

      const auditEvent = {
        timestamp: new Date().toISOString(),
        eventType: 'AUTH_FAILED',
        severity: 'WARN',
        correlationId,
        tenantId: resolveTenantIdentifier(req),
        request: {
          method: req.method,
          path: req.originalUrl || req.url,
          clientIp: sanitizeString(clientIp),
          userAgent: sanitizeString(req.headers['user-agent'] || 'UNKNOWN'),
          query: sanitizePayload(req.query),
          // Sanitização estrita do corpo enviado pelo usuário
          body: sanitizePayload(req.body)
        },
        response: {
          statusCode: res.statusCode,
          statusMessage: res.statusMessage
        }
      };

      // Em produção, envie para seu logger estruturado (Pino, Winston, etc.)
      // Evite console.log genérico com interpolação de strings para manter o formato JSON
      process.stdout.write(JSON.stringify(auditEvent) + '\n');
    }
  });

  next();
}