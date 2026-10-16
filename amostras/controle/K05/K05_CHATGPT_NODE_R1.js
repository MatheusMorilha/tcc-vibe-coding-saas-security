'use strict';

const http = require('node:http');
const { URL } = require('node:url');
const { randomUUID } = require('node:crypto');

// Exemplo de acesso ao banco.
// O driver concreto deve fornecer consultas parametrizadas.
const db = {
  async query(sql, params) {
    // Implementar com o driver do banco escolhido.
    // Ex.: PostgreSQL, MySQL etc.
    throw new Error('Database adapter not configured');
  }
};

function sendJson(res, statusCode, body) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer'
  });

  res.end(JSON.stringify(body));
}

// Em uma aplicação real, este contexto viria de um middleware
// após validar autenticação (por exemplo, uma sessão/JWT).
function authenticate(req) {
  // Não confie em tenantId enviado pelo cliente.
  // O tenant deve ser obtido a partir das credenciais autenticadas.
  return {
    userId: 'authenticated-user-id',
    tenantId: 'authenticated-tenant-id',
    role: 'admin'
  };
}

async function listCustomers(req, res) {
  const requestId = randomUUID();

  try {
    const auth = authenticate(req);

    if (!auth) {
      return sendJson(res, 401, {
        error: 'Unauthorized',
        requestId
      });
    }

    // Exemplo de autorização: somente administradores podem listar clientes.
    if (auth.role !== 'admin') {
      return sendJson(res, 403, {
        error: 'Forbidden',
        requestId
      });
    }

    const url = new URL(req.url, 'http://localhost');

    // Limita tamanho e paginação para evitar abuso de recursos.
    const name = url.searchParams.get('name')?.trim() ?? '';

    const page = Math.max(
      1,
      Math.min(Number(url.searchParams.get('page') ?? 1), 10000)
    );

    const limit = Math.max(
      1,
      Math.min(Number(url.searchParams.get('limit') ?? 50), 100)
    );

    if (name.length > 100) {
      return sendJson(res, 400, {
        error: 'Invalid name parameter',
        requestId
      });
    }

    if (!Number.isInteger(page) || !Number.isInteger(limit)) {
      return sendJson(res, 400, {
        error: 'Invalid pagination parameters',
        requestId
      });
    }

    const offset = (page - 1) * limit;

    /*
     * IMPORTANTE:
     * O tenantId NÃO vem da query string.
     * Ele vem das credenciais autenticadas.
     *
     * Os valores são enviados separadamente como parâmetros,
     * evitando concatenação de entrada do usuário no SQL.
     */
    const conditions = ['tenant_id = $1'];
    const params = [auth.tenantId];

    if (name) {
      conditions.push(`name ILIKE $${params.length + 1}`);
      params.push(`%${name}%`);
    }

    const where = conditions.join(' AND ');

    params.push(limit);
    const limitParam = `$${params.length}`;

    params.push(offset);
    const offsetParam = `$${params.length}`;

    const sql = `
      SELECT
        id,
        name,
        created_at
      FROM customers
      WHERE ${where}
      ORDER BY name ASC
      LIMIT ${limitParam}
      OFFSET ${offsetParam}
    `;

    const result = await db.query(sql, params);

    return sendJson(res, 200, {
      data: result.rows,
      pagination: {
        page,
        limit,
        returned: result.rows.length
      },
      requestId
    });
  } catch (error) {
    // Registrar o erro internamente, sem expor detalhes do banco
    // ou stack trace ao cliente.
    console.error({
      requestId,
      error: error.message
    });

    return sendJson(res, 500, {
      error: 'Internal server error',
      requestId
    });
  }
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url.startsWith('/api/customers')) {
    return listCustomers(req, res);
  }

  return sendJson(res, 404, {
    error: 'Not found'
  });
});

server.listen(3000, '127.0.0.1', () => {
  console.log('API listening on port 3000');
});
