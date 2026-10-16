'use strict';

const http = require('node:http');
const { URL } = require('node:url');

// Exemplo de conexão com PostgreSQL.
// Em produção, configure a URL por variável de ambiente.
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: true }
    : false
});

/**
 * Limites defensivos para a entrada da API.
 */
const MAX_NAME_LENGTH = 100;
const MAX_PAGE_SIZE = 100;
const DEFAULT_PAGE_SIZE = 20;

/**
 * Exemplo de autenticação.
 *
 * Em uma aplicação real, o token deve ser validado por um mecanismo
 * de autenticação centralizado (por exemplo, JWT assinado ou sessão).
 *
 * O middleware deve retornar informações obtidas de uma fonte confiável,
 * e NÃO aceitar tenantId/permissões vindos diretamente do cliente.
 */
async function authenticate(req) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith('Bearer ')) {
    return null;
  }

  const token = authorization.slice('Bearer '.length).trim();

  if (!token) {
    return null;
  }

  // Substitua pela validação real do token.
  // Exemplo conceitual:
  //
  // const payload = await verifyJwt(token);
  // return {
  //   userId: payload.sub,
  //   tenantId: payload.tenantId,
  //   permissions: payload.permissions
  // };

  return {
    userId: 'authenticated-user',
    tenantId: 'tenant-from-validated-token',
    permissions: ['customers:read']
  };
}

/**
 * Verifica autorização.
 */
function canReadCustomers(user) {
  return user &&
    Array.isArray(user.permissions) &&
    user.permissions.includes('customers:read');
}

/**
 * Validação do parâmetro "name".
 */
function validateName(value) {
  if (value === null || value === undefined || value === '') {
    return {
      valid: true,
      value: null
    };
  }

  if (typeof value !== 'string') {
    return {
      valid: false,
      error: 'O parâmetro "name" deve ser uma string.'
    };
  }

  const name = value.trim();

  if (name.length > MAX_NAME_LENGTH) {
    return {
      valid: false,
      error: `O parâmetro "name" deve possuir no máximo ${MAX_NAME_LENGTH} caracteres.`
    };
  }

  return {
    valid: true,
    value: name
  };
}

/**
 * GET /api/customers?name=empresa
 *
 * A consulta é sempre limitada ao tenant do usuário autenticado.
 */
async function listCustomers(req, res) {
  const user = await authenticate(req);

  if (!user) {
    return sendJson(res, 401, {
      error: 'Não autenticado.'
    });
  }

  if (!canReadCustomers(user)) {
    return sendJson(res, 403, {
      error: 'Acesso negado.'
    });
  }

  const requestUrl = new URL(
    req.url,
    `http://${req.headers.host || 'localhost'}`
  );

  const nameValidation = validateName(
    requestUrl.searchParams.get('name')
  );

  if (!nameValidation.valid) {
    return sendJson(res, 400, {
      error: nameValidation.error
    });
  }

  const requestedLimit = Number(
    requestUrl.searchParams.get('limit') || DEFAULT_PAGE_SIZE
  );

  const limit =
    Number.isInteger(requestedLimit) &&
    requestedLimit > 0 &&
    requestedLimit <= MAX_PAGE_SIZE
      ? requestedLimit
      : DEFAULT_PAGE_SIZE;

  const requestedPage = Number(
    requestUrl.searchParams.get('page') || 1
  );

  const page =
    Number.isInteger(requestedPage) && requestedPage > 0
      ? requestedPage
      : 1;

  const offset = (page - 1) * limit;

  const params = [user.tenantId];
  const conditions = ['tenant_id = $1'];

  if (nameValidation.value !== null) {
    params.push(`%${nameValidation.value}%`);
    conditions.push(`name ILIKE $${params.length}`);
  }

  params.push(limit);
  const limitParameter = params.length;

  params.push(offset);
  const offsetParameter = params.length;

  const sql = `
    SELECT
      id,
      name,
      created_at
    FROM customers
    WHERE ${conditions.join(' AND ')}
    ORDER BY name ASC, id ASC
    LIMIT $${limitParameter}
    OFFSET $${offsetParameter}
  `;

  try {
    const result = await pool.query(sql, params);

    return sendJson(res, 200, {
      data: result.rows,
      pagination: {
        page,
        limit,
        count: result.rows.length
      }
    });
  } catch (error) {
    // Não exponha detalhes internos do banco para o cliente.
    console.error('Erro ao listar clientes:', error);

    return sendJson(res, 500, {
      error: 'Erro interno do servidor.'
    });
  }
}

/**
 * Pequeno helper para respostas JSON.
 */
function sendJson(res, statusCode, body) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });

  res.end(JSON.stringify(body));
}

/**
 * Roteamento.
 */
const server = http.createServer(async (req, res) => {
  try {
    if (
      req.method === 'GET' &&
      new URL(
        req.url,
        `http://${req.headers.host || 'localhost'}`
      ).pathname === '/api/customers'
    ) {
      return await listCustomers(req, res);
    }

    return sendJson(res, 404, {
      error: 'Rota não encontrada.'
    });
  } catch (error) {
    console.error('Erro não tratado:', error);

    if (!res.headersSent) {
      return sendJson(res, 500, {
        error: 'Erro interno do servidor.'
      });
    }

    res.end();
  }
});

const port = Number(process.env.PORT || 3000);

server.listen(port, () => {
  console.log(`API executando na porta ${port}`);
});
