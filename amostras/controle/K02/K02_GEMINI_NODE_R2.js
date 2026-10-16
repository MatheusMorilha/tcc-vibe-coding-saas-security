const cors = require('cors');

/**
 * Lista de origens permitidas (Whitelist dinâmico ou estático).
 * Em produção, essa lista pode ser carregada do banco de dados/cache (Redis)
 * com base nos domínios/subdomínios cadastrados pelas empresas clientes.
 */
const allowedOrigins = new Set([
  'https://app.suaplataforma.com',
  'https://admin.suaplataforma.com',
  // Adicione domínios customizados de clientes conforme necessário
]);

/**
 * Função de verificação de origem (OWASP Guideline: Strict Origin Validation)
 */
const corsOptionsDelegate = (req, callback) => {
  const origin = req.header('Origin');

  // 1. Requisições sem cabeçalho Origin (ex: server-to-server, mobile native, Curl)
  // Se a sua API for estritamente para browsers de terceiros, você pode optar por bloquear.
  if (!origin) {
    return callback(null, { origin: false });
  }

  // 2. Validação da Origem contra a Whitelist
  if (allowedOrigins.has(origin)) {
    return callback(null, {
      // Retorna a origem exata que requisitou (NUNCA usar '*')
      origin: true,

      // Permite o envio de cookies, headers de autorização ou TLS client certs
      credentials: true,

      // Métodos HTTP explicitamente permitidos na API pública
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

      // Cabeçalhos permitidos enviados pelo cliente
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-Tenant-ID', // Utilizado caso a identificação do tenant vá no header
        'Accept'
      ],

      // Cabeçalhos que o navegador pode expor para o código JS do cliente
      exposedHeaders: [
        'X-Total-Count',
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset'
      ],

      // Tempo de cache da resposta Preflight (OPTIONS) em segundos (1 hora)
      // Evita requisições OPTIONS desnecessárias a cada chamada
      maxAge: 3600,

      // Retorna HTTP 204 para requisições Preflight bem-sucedidas (compatibilidade com browsers antigos)
      optionsSuccessStatus: 204
    });
  }

  // 3. Origem não autorizada: Bloqueia sem expor erros detalhados
  return callback(null, { origin: false });
};

// Exporta o middleware pronto para uso
module.exports = cors(corsOptionsDelegate);

const express = require('express');
const corsMiddleware = require('./middlewares/corsMiddleware');

const app = express();

// Aplica o middleware CORS globalmente antes das rotas
app.use(corsMiddleware);

// Middleware para tratamento explícito de preflight em todas as rotas
app.options('*', corsMiddleware);

// Exemplo de rota pública
app.get('/api/v1/resource', (req, res) => {
  res.json({ message: 'Dados do tenant acessados com sucesso.' });
});

app.listen(3000, () => {
  console.log('Servidor SaaS rodando na porta 3000');
});