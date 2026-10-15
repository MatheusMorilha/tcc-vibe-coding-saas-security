const http = require('node:http');
const {URL }= require('node:url');

// Exemplo de camada de persistência.
// Em uma aplicação real, substitua por PostgreSQL, MySQL etc.
const db = {
  async transaction(callback) {
    // Iniciar transação real aqui.
    return callback({
      async query(sql, params) {
        // Implementação real do driver do banco.
        throw new Error('Implementar acesso ao banco');
      },
      async commit() {},
      async rollback() {}
    });
  }
};

// Middleware/autenticação hipotético.
// O contexto deve vir de um token/sessão já validado.
function authenticate(req) {
  // Exemplo:
  // return {
  //   userId: 'user-123',
  //   tenantId: 'company-456'
  // };

  return {
    userId: req.headers['x-user-id'],
    tenantId: req.headers['x-tenant-id']
  };
}

function sendJson(res, statusCode, body) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8'
  });

  res.end(JSON.stringify(body));
}

async function approveExpense(req, res, expenseId) {
  const auth = authenticate(req);

  if (!auth.userId|| !auth.tenantId) {
    return sendJson(res, 401, {
      error: 'UNAUTHENTICATED',
      message: 'Usuário não autenticado.'
    });
  }

  try {
    const result = await db.transaction(async (tx)=> {
      /*
       * O tenant_id é usado na consulta.
       * Assim, mesmo que alguém forneça o ID de uma despesa
       * pertencente a outra empresa, ela não será encontrada.
       */
      const expenseResult = await tx.query(
        `
        SELECT
          id,
          tenant_id,
          status
        FROM expense_requests
        WHERE id = $1
          AND tenant_id = $2
        FOR UPDATE
        `,
        [expenseId, auth.tenantId]
      );

      if (expenseResult.rows.length === 0) {
        return {
          type: 'not_found'
        };
      }

      const expense = expenseResult.rows[0];

      if (expense.status!== 'PENDING') {
        return {
          type: 'invalid_state',
          currentStatus: expense.status
        };
      }

      /*
       * A aprovação também é registrada com o usuário responsável
       * e dentro do mesmo tenant.
       */
      const updateResult = await tx.query(
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
          status,
          approved_by,
          approved_at
        `,
        [auth.userId, expenseId, auth.tenantId]
      );

      if (updateResult.rows.length === 0) {
        return {
          type: 'conflict'
        };
      }

      return {
        type: 'success',
        expense: updateResult.rows[0]
      };
    });

    if (result.type=== 'not_found') {
      return sendJson(res, 404, {
        error: 'EXPENSE_NOT_FOUND',
        message: 'Solicitação de despesa não encontrada.'
      });
    }

    if (result.type=== 'invalid_state') {
      return sendJson(res, 409, {
        error: 'INVALID_EXPENSE_STATE',
        message: 'A solicitação não está pendente e não pode ser aprovada.',
        currentStatus: result.currentStatus
      });
    }

    if (result.type=== 'conflict') {
      return sendJson(res, 409, {
        error: 'APPROVAL_CONFLICT',
        message: 'A solicitação foi alterada antes da aprovação.'
      });
    }

    return sendJson(res, 200, {
      success: true,
      message: 'Solicitação de despesa aprovada com sucesso.',
      expense: result.expense
    });
  }catch (error) {
    console.error('Erro ao aprovar despesa:', error);

    return sendJson(res, 500, {
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Não foi possível aprovar a solicitação.'
    });
  }
}

const server = http.createServer(async (req, res)=> {
  const url = new URL(req.url, 'http://localhost');

  const match = url.pathname.match(
    /^\/api\/expenses\/([^/]+)\/approve$/
  );

  if (req.method=== 'POST' && match) {
    const expenseId = match[1];

    await approveExpense(req, res, expenseId);
    return;
  }

  sendJson(res, 404, {
    error: 'NOT_FOUND',
    message: 'Rota não encontrada.'
  });
});

server.listen(3000, ()=> {
  console.log('API executando em http://localhost:3000');
});