const express = require('express');
const cors = require('cors');

const app = express();

/**
 * Lista de domínios ou origens permitidas dinamicamente.
 * Em produção, essa lista/verificação pode vir de um cache (Redis) ou do banco de dados.
 */
const allowedOrigins = [
  'https://app.seusaas.com',
  'https://painel.seusaas.com',
];

/**
 * Função para validação dinâmica de origens permitidas.
 * Suporta origens pré-aprovadas ou validação de subdomínios/custom domains de locatários.
 */
const isOriginAllowed = (origin, callback) => {
  // Permite requisições sem 'Origin' (como chamadas Server-to-Server, cURL ou apps mobile nativos)
  if (!origin) {
    return callback(null, true);
  }

  // 1. Verificação em lista estática de origens confiáveis
  if (allowedOrigins.includes(origin)) {
    return callback(null, true);
  }

  // 2. Regra de validação para domínios/subdomínios de locatários
  // Exemplo: permite qualquer subdomínio do SaaS (https://empresaA.seusaas.com)
  const tenantSubdomainRegex = /^https:\/\/[a-z0-9-]+\.seusaas\.com$/i;
  if (tenantSubdomainRegex.test(origin)) {
    return callback(null, true);
  }

  // Exemplo de integração futura com DB/Cache para Domínios Customizados (ex: https://portal.cliente.com)
  // const isCustomDomain = await checkCustomDomainInRedis(origin);
  // if (isCustomDomain) return callback(null, true);

  // Rejeita a origem caso não corresponda a nenhuma regra
  return callback(new Error(`Origem não permitida pelo CORS: ${origin}`));
};

/**
 * Configuração do Middleware CORS
 */
const corsOptions = {
  origin: isOriginAllowed,

  // Obrigatório para permitir o envio de cookies de sessão / autorização entre domínios
  credentials: true,

  // Métodos HTTP permitidos nos endpoints públicos
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],

  // Cabeçalhos que o cliente pode enviar na requisição
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'X-Tenant-ID', // Cabeçalho opcional para identificação explícita do locatário
  ],

  // Cabeçalhos que o navegador pode expor ao JavaScript da aplicação cliente
  exposedHeaders: ['X-Total-Count', 'X-Session-Expires-At'],

  // Tempo (em segundos) que os navegadores podem fazer cache da resposta Preflight (OPTIONS)
  // Reduz drasticamente a quantidade de requisições OPTIONS no backend
  maxAge: 86400, // 24 horas

  // Retorna HTTP 204 para requisições OPTIONS bem-sucedidas (compatibilidade com navegadores legados)
  optionsSuccessStatus: 204,
};

// Aplica o middleware de forma global na API
app.use(cors(corsOptions));

// Tratamento de erro específico para bloqueio de CORS
app.use((err, req, res, next) => {
  if (err.message && err.message.startsWith('Origem não permitida pelo CORS')) {
    return res.status(403).json({
      error: 'CORS_POLICY_VIOLATION',
      message: 'Acesso negado: Origem não autorizada a consumir esta API.',
    });
  }
  next(err);
});

module.exports = app;