const express = require('express');
const app = express();

/**
 * 1. Lista Branca (Allowlist) de Origens Permitidas
 * Mantida via variáveis de ambiente para fácil auditoria e atualização.
 * Suporta origens confiáveis globais e subdomínios de locatários/parceiros.
 */
const ALLOWED_ORIGINS = new Set([
  'https://app.suaplataforma.com',
  'https://admin.suaplataforma.com',
  // Adicione domínios de parceiros ou origens homologadas aqui
]);

/**
 * Função para validar a origem da requisição.
 * Para SaaS com domínios customizados por cliente, pode-se realizar consulta
 * em cache (Redis) ou validação via expressão regular para subdomínios confiáveis.
 */
function isOriginAllowed(origin){
  if (!origin) return false;

  // Verificação direta na lista branca
  if (ALLOWED_ORIGINS.has(origin)) return true;

  // Exemplo de permissão dinâmica para subdomínios *.suaplataforma.com em HTTPS
  const tenantSubdomainRegex = /^https:\/\/[a-z0-9-]+\.suaplataforma\.com$/i;
  if (tenantSubdomainRegex.test(origin)) return true;

  return false;
}

/**
 * Middleware de CORS Seguro (Alinhado com OWASP Top 10)
 */
const corsMiddleware = (req, res, next) => {
  const origin = req.headers.origin;

  // Se a requisição contiver o cabeçalho Origin, realizamos a validação
  if (origin) {
    if (isOriginAllowed(origin)) {
      // Configuração dinâmica da origem permitida (OWASP A01:2021 / Security Misconfiguration)
      res.setHeader('Access-Control-Allow-Origin', origin);

      // Requisito do prompt: Permitir o envio de credenciais de sessão (cookies, HttpOnly, etc)
      res.setHeader('Access-Control-Allow-Credentials', 'true');

      // Indica a proxies e CDNs que a resposta varia com base na origem da requisição
      res.setHeader('Vary', 'Origin');
    } else {
      // Bloqueio imediato para origens não autorizadas
      return res.status(403).json({
        error: 'Access Denied',
        message: 'A origem da requisição não é permitida por política de CORS.'
      });
    }
  }

  // Tratamento da requisição Preflight (OPTIONS)
  if (req.method === 'OPTIONS') {
    // Métodos estritamente necessários para a API
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');

    // Lista delimitada de cabeçalhos permitidos (Evita exposição indevida de headers sensíveis)
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Tenant-ID');

    // Tempo em segundos que o navegador pode armazenar em cache o resultado do preflight (10 min)
    res.setHeader('Access-Control-Max-Age', '600');

    return res.status(204).end();
  }

  next();
};

module.exports = corsMiddleware;