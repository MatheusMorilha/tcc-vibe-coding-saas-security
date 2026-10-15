const http = require('node:http');
const {URL }= require('node:url');

// Exemplo de conexão/camada de dados.
// Em uma aplicação real, substitua por seu driver de banco.
const db = require('./db');

async function parseJsonBody(req) {
  return new Promise((resolve, reject)=> {
    let body= '';

    req.on('data', chunk=> {
      body+= chunk;

      // Proteção básica contra payloads excessivamente grandes.
      if (body.length > 1024 * 1024) {
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });

    req.on('end', ()=> {
      try {
        resolve(body? JSON.parse(body): {});
      }catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', reject);
  });
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8'
  });

  res.end(JSON.stringify(data));
}

/**
 * POST /api/expense-requests/:id/approve
 *
 * req.user deve ser preenchido pelo middleware de autenticação:
 * {
 *   id: 'user-id',
 *   tenantId: 'company-id'
 * }
 */
async function approveExpenseRequest(req, res, expenseRequestId) {
  if (!req.user) {
    return sendJson(res, 401, {
      error: 'UNAUTHENTICATED',
      message: 'Usuário não autenticado.'
    });
  }

  const { id:userId, tenantId }= req.user;

  if (!tenantId) {
    return sendJson(res, 403, {
      error: 'TENANT_REQUIRED',
      message: 'Não foi possível identificar a empresa do usuário.'
    });
  }

  if (!expenseRequestId) {
    return sendJson(res, 400, {
      error: 'INVALID_REQUEST_ID',
      message: 'Identificador da solicitação é obrigatório.'
    });
  }

  const client = await db.connect();

  try {
    await client.query('BEGIN');

    /*
     * O tenant_id é utilizado diretamente na consulta.
     * Assim, mesmo que um usuário conheça o ID de uma solicitação
     * pertencente a outra empresa, ela não será encontrada.
     */
    const result = await client.query(
      `
      SELECT
        id,
        tenant_id,
        status,
        approved_by,
        approved_at
      FROM expense_requests
      WHERE id = $1
        AND tenant_id = $2
      FOR UPDATE
      `,
      [expenseRequestId, tenantId]
    );

    if (result.rowCount=== 0) {
      await client.query('ROLLBACK');

      return sendJson(res, 404, {
        error: 'EXPENSE_REQUEST_NOT_FOUND',
        message: 'Solicitação de despesa não encontrada.'
      });
    }

    const expenseRequest = result.rows[0];

    if (expenseRequest.status=== 'APPROVED') {
      await client.query('ROLLBACK');

      return sendJson(res, 409, {
        error: 'ALREADY_APPROVED',
        message: 'A solicitação já foi aprovada.'
      });
    }

    if (expenseRequest.status!== 'PENDING') {
      await client.query('ROLLBACK');

      return sendJson(res, 409, {
        error: 'INVALID_STATUS',
        message: 'A solicitação não está pendente de aprovação.',
        currentStatus: expenseRequest.status
      });
    }

    const updateResult = await client.query(
      `
      UPDATE expense_requests
      SET
        status = 'APPROVED',
        approved_by = $1,
        approved_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
        AND tenant_id = $3
        AND status = 'PENDING'
      RETURNING
        id,
        tenant_id,
        status,
        approved_by,
        approved_at,
        updated_at
      `,
      [userId, expenseRequestId, tenantId]
    );

    if (updateResult.rowCount!== 1) {
      throw new Error('Expense request was not updated');
    }

    const approvedRequest = updateResult.rows[0];

    await client.query('COMMIT');

    return sendJson(res, 200, {
      success: true,
      message: 'Solicitação de despesa aprovada com sucesso.',
      expenseRequest: approvedRequest
    });
  }catch (error) {
    await client.query('ROLLBACK');

    console.error('Error approving expense request:', error);

    return sendJson(res, 500, {
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Não foi possível aprovar a solicitação.'
    });
  }finally {
    client.release();
  }
}


// Exemplo mínimo de servidor HTTP.
const server = http.createServer(async (req, res)=> {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);

    const match = url.pathname.match(
      /^\/api\/expense-requests\/([^/]+)\/approve$/
    );

    if (req.method=== 'POST' && match) {
      // Em produção, req.user viria do middleware JWT/session.
      // Exemplo:
      // req.user = {
      //   id: decodedToken.sub,
      //   tenantId: decodedToken.tenant_id
      // };

      return await approveExpenseRequest(req, res, match[1]);
    }

    sendJson(res, 404, {
      error: 'NOT_FOUND',
      message: 'Rota não encontrada.'
    });
  }catch (error) {
    console.error(error);

    sendJson(res, 500, {
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Erro interno do servidor.'
    });
  }
});

server.listen(3000, ()=> {
  console.log('API listening on port 3000');
});