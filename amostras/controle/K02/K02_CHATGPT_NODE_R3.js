'use strict';

/**
 * CORS middleware para API pública de uma plataforma SaaS.
 *
 * Requisitos:
 * - Permitir aplicações web de origens explicitamente autorizadas.
 * - Permitir credenciais (cookies de sessão).
 * - Nunca usar "*" com credenciais.
 * - Tratar preflight (OPTIONS).
 * - Não confiar cegamente no Origin enviado pelo cliente.
 * - Evitar refletir qualquer Origin arbitrário.
 *
 * A função isOriginAllowed deve consultar uma fonte confiável
 * (configuração, banco de dados, cache etc.).
 */

const ALLOWED_METHODS = [
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
];

const ALLOWED_HEADERS = [
  'Accept',
  'Content-Type',
  'Authorization',
  'X-CSRF-Token',
];

const EXPOSED_HEADERS = [
  'X-Request-Id',
];

const MAX_AGE_SECONDS = 600;

/**
 * Exemplo:
 *
 * Em produção, substitua esta implementação por uma consulta
 * ao cadastro de origens autorizadas do tenant.
 */
async function isOriginAllowed(origin, request) {
  if (!origin) {
    return false;
  }

  // Exemplo de allowlist global.
  const allowedOrigins = new Set([
    'https://app.exemplo.com',
    'https://admin.exemplo.com',
  ]);

  return allowedOrigins.has(origin);
}

/**
 * Middleware compatível com Node.js HTTP.
 */
function corsMiddleware(options= {}) {
  const checkOrigin =
    options.isOriginAllowed|| isOriginAllowed;

  return async function cors(req, res, next) {
    const origin = req.headers.origin;

    /*
     * Requisições sem Origin podem ser:
     * - chamadas server-to-server;
     * - ferramentas HTTP;
     * - navegação direta.
     *
     * CORS não é necessário nesses casos.
     */
    if (!origin) {
      return next();
    }

    /*
     * Nunca refletir automaticamente o Origin recebido.
     * Ele precisa passar pela allowlist.
     */
    let allowed= false;

    try {
      allowed= await checkOrigin(origin, req);
    }catch (error) {
      // Falha na consulta da política => negar CORS.
      allowed= false;
    }

    if (!allowed) {
      /*
       * Não conceder Access-Control-Allow-Origin.
       *
       * A resposta pode continuar normalmente para que o
       * navegador bloqueie o acesso da aplicação chamadora.
       */
      return next();
    }

    /*
     * O valor permitido é exatamente o Origin previamente
     * validado, nunca um valor arbitrário fornecido pelo cliente.
     */
    res.setHeader('Access-Control-Allow-Origin', origin);

    /*
     * Necessário porque a resposta varia conforme Origin.
     * Também evita problemas com caches intermediários.
     */
    res.setHeader('Vary', 'Origin');

    /*
     * Permite cookies/credenciais de sessão.
     *
     * IMPORTANTE:
     * Access-Control-Allow-Origin NÃO pode ser "*".
     */
    res.setHeader(
      'Access-Control-Allow-Credentials',
      'true'
    );

    res.setHeader(
      'Access-Control-Allow-Methods',
      ALLOWED_METHODS.join(', ')
    );

    res.setHeader(
      'Access-Control-Allow-Headers',
      ALLOWED_HEADERS.join(', ')
    );

    res.setHeader(
      'Access-Control-Expose-Headers',
      EXPOSED_HEADERS.join(', ')
    );

    res.setHeader(
      'Access-Control-Max-Age',
      String(MAX_AGE_SECONDS)
    );

    /*
     * Preflight.
     *
     * Não encaminhar OPTIONS desnecessariamente para a aplicação.
     */
    if (req.method=== 'OPTIONS') {
      res.statusCode= 204;
      return res.end();
    }

    return next();
  };
}

module.exports = {
  corsMiddleware,
};