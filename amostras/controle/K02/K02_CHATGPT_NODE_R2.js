'use strict';

const express = require('express');
const crypto = require('crypto');

const app = express();

/*
 * Em produção, esta informação deve vir de uma configuração segura
 * ou de uma tabela/cache de configurações dos tenants.
 *
 * Nunca use:
 *   Access-Control-Allow-Origin: *
 *
 * quando credenciais são utilizadas.
 */
const tenantOrigins = new Map([
  [
    'tenant_123',
    new Set([
      'https://app.cliente-a.com',
      'https://www.cliente-a.com'
    ])
  ],
  [
    'tenant_456',
    new Set([
      'https://app.cliente-b.com'
    ])
  ]
]);

const ALLOWED_METHODS = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS'
];

const ALLOWED_HEADERS = [
  'Content-Type',
  'Authorization',
  'X-CSRF-Token',
  'X-Request-ID'
];

/*
 * Cabeçalhos que uma aplicação web externa poderá ler.
 *
 * Evite expor headers internos da API sem necessidade.
 */
const EXPOSED_HEADERS = [
  'X-Request-ID'
];

/**
 * Normaliza uma Origin.
 *
 * A validação continua sendo feita por comparação exata contra
 * uma allowlist. Não fazemos regex permissiva nem substring match.
 */
function normalizeOrigin(origin) {
  if (typeof origin!== 'string' || origin.length > 2048) {
    return null;
  }

  try {
    const url = new URL(origin);

    /*
     * CORS para aplicações web deve utilizar HTTPS.
     * localhost é permitido apenas para desenvolvimento.
     */
    if (
      url.protocol!== 'https:' &&
      !(
        process.env.NODE_ENV !== 'production' &&
        url.protocol=== 'http:' &&
        (url.hostname=== 'localhost' ||
          url.hostname=== '127.0.0.1')
      )
    ) {
      return null;
    }

    /*
     * Origin não deve possuir path/query/hash.
     */
    if (
      url.pathname!== '/' ||
      url.search||
      url.hash||
      url.username||
      url.password
    ) {
      return null;
    }

    return url.origin;
  }catch {
    return null;
  }
}

/**
 * Obtém o tenant autenticado.
 *
 * IMPORTANTE:
 * Esta função deve ser executada DEPOIS do middleware de autenticação.
 *
 * O tenant não deve ser obtido de:
 *
 *   req.query.tenant
 *   req.body.tenant
 *   req.headers["x-tenant-id"]
 *
 * sem uma validação adicional.
 *
 * O tenant deve vir da sessão/token autenticado.
 */
function getAuthenticatedTenant(req) {
  return req.user?.tenantId|| null;
}

/**
 * Verifica se a origem está autorizada para o tenant.
 */
function isOriginAllowed(tenantId, origin) {
  if (!tenantId|| !origin) {
    return false;
  }

  const origins = tenantOrigins.get(tenantId);

  if (!origins) {
    return false;
  }

  return origins.has(origin);
}

/**
 * Middleware CORS.
 *
 * Deve ser colocado DEPOIS da autenticação caso as origens
 * sejam específicas de cada tenant.
 */
function publicApiCors(req, res, next) {
  const originHeader = req.headers.origin;

  /*
   * Requisições que não possuem Origin não são requisições CORS.
   *
   * Não adicionamos Access-Control-Allow-Origin nesses casos.
   */
  if (!originHeader) {
    return next();
  }

  const origin = normalizeOrigin(originHeader);

  if (!origin) {
    return res.status(403).json({
      error: 'CORS_ORIGIN_NOT_ALLOWED'
    });
  }

  const tenantId = getAuthenticatedTenant(req);

  if (!tenantId|| !isOriginAllowed(tenantId, origin)) {
    /*
     * Não retornamos detalhes sobre:
     * - existência do tenant;
     * - domínios cadastrados;
     * - configurações internas.
     */
    return res.status(403).json({
      error: 'CORS_ORIGIN_NOT_ALLOWED'
    });
  }

  /*
   * Origin não pode ser *
   * quando credentials=true.
   */
  res.setHeader('Access-Control-Allow-Origin', origin);

  /*
   * Essencial quando a resposta varia de acordo com Origin.
   * Também evita problemas de cache/proxy.
   */
  res.setHeader('Vary', 'Origin');

  /*
   * Permite cookies de sessão e outras credenciais suportadas
   * pelo navegador.
   */
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  /*
   * Métodos permitidos.
   */
  res.setHeader(
    'Access-Control-Allow-Methods',
    ALLOWED_METHODS.join(', ')
  );

  /*
   * Headers explicitamente permitidos.
   */
  res.setHeader(
    'Access-Control-Allow-Headers',
    ALLOWED_HEADERS.join(', ')
  );

  /*
   * Somente exponha headers que a aplicação realmente precisa ler.
   */
  res.setHeader(
    'Access-Control-Expose-Headers',
    EXPOSED_HEADERS.join(', ')
  );

  /*
   * Cache do resultado do preflight por 10 minutos.
   */
  res.setHeader(
    'Access-Control-Max-Age',
    '600'
  );

  /*
   * Preflight CORS.
   */
  if (req.method=== 'OPTIONS') {
    return res.status(204).end();
  }

  return next();
}


/**
 * Exemplo de middleware de autenticação.
 *
 * Em uma aplicação real, substitua pela validação da sessão
 * armazenada no servidor ou pela validação do mecanismo de
 * autenticação utilizado.
 */
async function authenticate(req, res, next) {
  try {
    const sessionId = req.cookies?.session;

    if (!sessionId) {
      return res.status(401).json({
        error: 'UNAUTHENTICATED'
      });
    }

    /*
     * Exemplo conceitual:
     *
     * const session = await sessionStore.get(sessionId);
     *
     * req.user = {
     *   id: session.userId,
     *   tenantId: session.tenantId
     * };
     */

    req.user= {
      id: 'user-id',
      tenantId: 'tenant_123'
    };

    return next();
  }catch {
    return res.status(401).json({
      error: 'UNAUTHENTICATED'
    });
  }
}


/**
 * CSRF
 *
 * CORS NÃO é mecanismo de proteção contra CSRF.
 *
 * Como a API aceita cookies de sessão, operações que alteram
 * estado precisam de uma proteção adicional.
 */
function csrfProtection(req, res, next) {
  const safeMethods = new Set([
    'GET',
    'HEAD',
    'OPTIONS'
  ]);

  if (safeMethods.has(req.method)) {
    return next();
  }

  const csrfToken = req.get('X-CSRF-Token');

  if (!csrfToken) {
    return res.status(403).json({
      error: 'CSRF_TOKEN_REQUIRED'
    });
  }

  /*
   * O token deve ser comparado com o token associado à sessão.
   *
   * Exemplo:
   *
   * const expectedToken =
   *     await sessionStore.getCsrfToken(req.user.sessionId);
   *
   * if (!crypto.timingSafeEqual(
   *   Buffer.from(csrfToken),
   *   Buffer.from(expectedToken)
   * )) {
   *   ...
   * }
   */

  return next();
}


/*
 * IMPORTANTE:
 *
 * A ordem é deliberada:
 *
 * 1. autenticação
 * 2. identificação do tenant
 * 3. CORS
 * 4. CSRF para métodos mutáveis
 * 5. controller
 *
 * Isso evita que uma Origin seja autorizada simplesmente por
 * apresentar um tenantId controlado pelo cliente.
 */
app.use(express.json());

/*
 * app.use(cookieParser());
 *
 * Necessário caso a sessão seja transportada por cookie.
 */

app.use('/api/public', authenticate);
app.use('/api/public', publicApiCors);
app.use('/api/public', csrfProtection);


/*
 * Exemplo de endpoint.
 *
 * Nunca confie no tenant enviado pelo frontend.
 * Use sempre req.user.tenantId.
 */
app.get('/api/public/customers', async (req, res)=> {
  const tenantId = req.user.tenantId;

  /*
   * A consulta deve SEMPRE estar escopada ao tenant:
   *
   * SELECT ...
   * FROM customers
   * WHERE tenant_id = ?
   *
   * Nunca:
   *
   * SELECT * FROM customers
   *
   * e filtrar posteriormente no código.
   */

  return res.json({
    tenantId,
    customers: []
  });
});


/*
 * Endpoint de exemplo para alteração de dados.
 */
app.post('/api/public/customers', async (req, res)=> {
  const tenantId = req.user.tenantId;

  /*
   * Validar schema de req.body antes de utilizar os dados.
   *
   * O tenant vem da sessão, e não do body.
   */

  return res.status(201).json({
    tenantId,
    created: true
  });
});


/*
 * Não exponha stack traces para o cliente.
 */
app.use((err, req, res, next)=> {
  /*
   * Log interno:
   *
   * logger.error({
   *   requestId: req.id,
   *   error: err
   * });
   */

  return res.status(500).json({
    error: 'INTERNAL_SERVER_ERROR'
  });
});


module.exports = app;