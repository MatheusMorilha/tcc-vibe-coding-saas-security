const express = require('express');
const cors = require('cors');

const app = express();

/**
 * Simulação de busca/cache de domínios autorizados.
 * Em produção, utilize um cache em memória (ex: Redis) para validar
 * domínios customizados configurados pelos clientes do SaaS.
 */
const ALLOWED_STATIC_ORIGINS = new Set([
  'https://app.suaplataforma.com',
  'https://admin.suaplataforma.com',
  'https://suaplataforma.com'
]);

// Exemplo de regex para validar subdomínios do SaaS (ex: empresa.suaplataforma.com)
const SAAS_SUBDOMAIN_REGEX = /^https:\/\/[a-z0-9-]+\.suaplataforma\.com$/i;

async function isOriginAllowed(origin){
  // 1. Origens estáticas do núcleo da plataforma
  if (ALLOWED_STATIC_ORIGINS.has(origin)) {
    return true;
  }

  // 2. Subdomínios do SaaS
  if (SAAS_SUBDOMAIN_REGEX.test(origin)) {
    return true;
  }

  // 3. Domínios customizados de locatários (ex: portal.cliente.com.br)
  // Recomenda-se buscar em cache de alto desempenho (ex: Redis) para não onerar o banco de dados
  const isCustomDomain = await checkCustomDomainInCache(origin);
  if (isCustomDomain) {
    return true;
  }

  return false;
}

// Configuração do Middleware de CORS
const corsOptionsDelegate = async (req, callback) => {
  const origin = req.header('Origin');
  let corsOptions;

  // Requisições same-origin ou ferramentas como cURL/Postman não enviam o header Origin
  if (!origin) {
    // Permite a requisição sem adicionar headers de CORS
    corsOptions = { origin: false };
    return callback(null, corsOptions);
  }

  try {
    const allowed = await isOriginAllowed(origin);

    if (allowed) {
      corsOptions = {
        // Retorna a origem exata para satisfazer o requisito de credenciais
        origin: origin,
        // Habilita envio de cookies/credenciais de sessão
        credentials: true,
        // Métodos explicitamente autorizados na API pública
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        // Headers permitidos na requisição do cliente
        allowedHeaders: [
          'Content-Type',
          'Authorization',
          'X-Requested-With',
          'X-Tenant-ID'
        ],
        // Headers que o navegador do cliente pode ler na resposta
        exposedHeaders: ['X-Request-ID', 'Set-Cookie'],
        // Tempo em segundos que o navegador pode armazenar a resposta da preflight request (10 min)
        maxAge: 600,
        // Retorna HTTP 204 para requisições OPTIONS prévias (suporte legado)
        optionsSuccessStatus: 204
      };
    } else {
      // Origem não autorizada: desabilita o CORS na resposta (o navegador bloqueará a leitura)
      corsOptions = { origin: false };
    }

    callback(null, corsOptions);
  } catch (error) {
    // Em caso de falha de validação/infraestrutura, nega o CORS por padrão (Fail-Safe)
    callback(error, { origin: false });
  }
};

// Aplicação do Middleware globalmente na API pública
app.use(cors(corsOptionsDelegate));

// Exemplo de rota tratada
app.get('/api/v1/user/profile', (req, res) => {
  res.json({ message: 'Dados da sessão autenticada do locatário' });
});

// Exemplo de função de verificação no Redis (Stub)
async function checkCustomDomainInCache(origin){
  // ex: return await redisClient.sIsMember('tenant_custom_domains', origin);
  return false;
}