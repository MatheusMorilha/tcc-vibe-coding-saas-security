const cors = require('cors');

/**
 * Lista ou padrão de origens permitidas.
 * Em produção, defina no .env separando por vírgula.
 * Ex: ALLOWED_ORIGINS="https://app.suaplataforma.com,https://admin.suaplataforma.com"
 */
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((origin) => origin.trim())
  : ['http://localhost:3000', 'http://localhost:5173'];

/**
 * Expressão regular para validar domínios de clientes/locatários (ex: https://empresa.suaplataforma.com)
 */
const tenantSubdomainRegex = /^https:\/\/([a-z0-9-]+)\.suaplataforma\.com$/i;

/**
 * Opções de configuração do CORS com verificação dinâmica de origem
 */
const corsOptionsDelegate = (req, callback) => {
  const origin = req.header('Origin');

  // Permitir requisições sem header Origin (ex: chamadas server-to-server, Postman, mobile apps nativos)
  if (!origin) {
    return callback(null, { origin: true });
  }

  // Validação da Origem
  const isExplicitlyAllowed = allowedOrigins.includes(origin);
  const isTenantSubdomain = tenantSubdomainRegex.test(origin);

  if (isExplicitlyAllowed || isTenantSubdomain) {
    callback(null, {
      origin: true, // Reflete a origem exata enviada na requisição
      credentials: true, // Permite o envio de cookies de sessão e headers Authorization
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-Tenant-ID' // Header customizado opcional para identificação do locatário
      ],
      exposedHeaders: [
        'X-Total-Count',
        'X-Tenant-ID'
      ],
      maxAge: 86400 // Cache da requisição Preflight (OPTIONS) por 24 horas no navegador
    });
  } else {
    // Origem não autorizada: desabilita o CORS para esta requisição
    callback(null, { origin: false });
  }
};

/**
 * Middleware exportável pronto para uso no Express
 */
const corsMiddleware = cors(corsOptionsDelegate);

module.exports = corsMiddleware;