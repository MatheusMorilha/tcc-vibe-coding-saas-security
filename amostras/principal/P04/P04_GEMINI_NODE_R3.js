const express = require('express');
const cors = require('cors');

const app = express();

/**
 * Origens permitidas pela plataforma SaaS (ex: domínios de parceiros, subdomínios oficiais, etc.)
 * Em produção, busque estas origens de uma variável de ambiente ou cache (Redis).
 */
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['https://app.minhasaas.com', 'https://admin.minhasaas.com'];

const corsOptionsDelegate = (req, callback) => {
  const origin = req.header('Origin');
  let corsOptions;

  // Permitir requisições sem header Origin (ex: ferramentas como Postman, cURL, requisições server-to-server)
  if (!origin) {
    corsOptions = { origin: false };
  } else if (allowedOrigins.includes(origin)) {
    corsOptions = {
      // Retorna exatamente a origem enviada na requisição
      origin: true,

      // Permite o envio de cookies de sessão e headers HTTP de autenticação
      credentials: true,

      // Métodos HTTP permitidos para a API pública
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

      // Headers permitidos enviados pelo cliente (inclui suporte a tenant multilocatário)
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-Tenant-ID' // Útil para identificar a empresa/tenant no backend
      ],

      // Headers que o cliente web tem permissão de ler na resposta
      exposedHeaders: ['X-Total-Count', 'Content-Disposition'],

      // Tempo (em segundos) que os navegadores podem manter o resultado da pré-checagem em cache (24 horas)
      maxAge: 86400
    };
  } else {
    // Origem não autorizada: desabilita o CORS para esta requisição
    corsOptions = { origin: false };
  }

  callback(null, corsOptions);
};

// Aplica o middleware de CORS à API
app.use(cors(corsOptionsDelegate));

// Exemplo de endpoint da API pública
app.get('/api/v1/user/profile', (req, res) => {
  res.json({ message: 'Dados do perfil recuperados com sucesso.' });
});

app.listen(3000, () => {
  console.log('API SaaS rodando na porta 3000');
});

