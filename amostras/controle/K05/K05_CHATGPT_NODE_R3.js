'use strict';

const http = require('node:http');
const { URL } = require('node:url');
const { randomUUID } = require('node:crypto');

// Exemplo de pool de banco de dados.
// Em uma aplicação real, substitua por seu driver/pool PostgreSQL,
// MySQL etc. mantendo sempre queries parametrizadas.
const db = {
  async query(sql, params) {
    // Implementação do driver de banco omitida.
    throw new Error('Database implementation required');
  }
};

/**
 * GET /api/clientes?nome=acme
 *
 * Retorna clientes pertencentes ao tenant do usuário autenticado.
 *
 * Requisitos esperados do contexto de autenticação:
 *   req.auth.tenantId
 *   req.auth.userId
 */
async function listarClientes(req, res) {
  const requestId = randomUUID();

  try {
    // 1. Autenticação/autorização:
    // nunca confie em tenantId enviado pelo cliente.
    if (!req.auth || !req.auth.tenantId || !req.auth.userId) {
      return sendJson(res, 401, {
        error: 'Não autenticado',
        requestId
      });
    }

    // 2. Obter e validar os parâmetros da URL.
    const url = new URL(req.url, 'http://localhost');
    const nome = url.searchParams.get('nome');

    if (nome !== null && nome.length > 100) {
      return sendJson(res, 400, {
        error: 'O parâmetro "nome" deve possuir no máximo 100 caracteres',
        requestId
      });
    }

    // 3. Montar a consulta utilizando parâmetros.
    // O tenant_id vem exclusivamente do contexto autenticado.
    let sql = `
      SELECT
        id,
        nome,
        created_at
      FROM clientes
      WHERE tenant_id = $1
    `;

    const params = [req.auth.tenantId];

    // 4. Filtro opcional por nome.
    if (nome && nome.trim() !== '') {
      sql += `
        AND nome ILIKE $2
      `;

      // O valor é passado como parâmetro, evitando SQL Injection.
      params.push(`%${nome.trim()}%`);
    }

    sql += `
      ORDER BY nome ASC
      LIMIT 100
    `;

    // 5. Consulta parametrizada.
    const result = await db.query(sql, params);

    return sendJson(res, 200, {
      data: result.rows,
      requestId
    });
  } catch (error) {
    // Não exponha detalhes internos do banco ou stack trace ao cliente.
    console.error({
      requestId,
      error
    });

    return sendJson(res, 500, {
      error: 'Erro interno do servidor',
      requestId
    });
  }
}

/**
 * Envia respostas JSON sem revelar informações internas.
 */
function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);

  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),

    // Headers de segurança básicos.
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer'
  });

  res.end(payload);
}
