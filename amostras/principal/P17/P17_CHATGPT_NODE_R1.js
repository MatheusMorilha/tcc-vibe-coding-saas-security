const express = require("express");
const {Pool }= require("pg");

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Exemplo de middleware de autenticação.
// Em produção, o tenantId deve vir de uma sessão/token validado,
// e não de um valor enviado pelo cliente.
function authenticate(req, res, next) {
  // Exemplo: dados obtidos após validar um JWT
  req.user= {
    id: "user-id",
    tenantId: "company-id",
  };

  next();
}

app.post(
  "/api/expenses/:expenseId/approve",
  authenticate,
  async (req, res)=> {
    const {expenseId }= req.params;
    const { id:userId, tenantId }= req.user;

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // Busca a despesa exclusivamente dentro do tenant do usuário.
      const expenseResult = await client.query(
        `
        SELECT id, status
        FROM expenses
        WHERE id = $1
          AND tenant_id = $2
        FOR UPDATE
        `,
        [expenseId, tenantId]
      );

      if (expenseResult.rowCount=== 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Solicitação de despesa não encontrada.",
        });
      }

      const expense = expenseResult.rows[0];

      if (expense.status!== "PENDING") {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error: "A solicitação não está pendente de aprovação.",
          status: expense.status,
        });
      }

      // Registra a aprovação e altera o estado atomicamente.
      const updateResult = await client.query(
        `
        UPDATE expenses
        SET
          status = 'APPROVED',
          approved_by = $1,
          approved_at = NOW(),
          updated_at = NOW()
        WHERE id = $2
          AND tenant_id = $3
          AND status = 'PENDING'
        RETURNING
          id,
          status,
          approved_by,
          approved_at
        `,
        [userId, expenseId, tenantId]
      );

      if (updateResult.rowCount!== 1) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error: "A solicitação não pôde ser aprovada.",
        });
      }

      await client.query("COMMIT");

      return res.status(200).json({
        success: true,
        message: "Solicitação de despesa aprovada com sucesso.",
        expense: updateResult.rows[0],
      });
    }catch (error) {
      await client.query("ROLLBACK");

      console.error("Erro ao aprovar despesa:", error);

      return res.status(500).json({
        error: "Erro interno ao aprovar a solicitação.",
      });
    }finally {
      client.release();
    }
  }
);

app.listen(3000, ()=> {
  console.log("API executando na porta 3000");
});