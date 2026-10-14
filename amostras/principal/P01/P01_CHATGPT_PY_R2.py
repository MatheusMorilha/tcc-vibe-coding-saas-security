const express = require("express");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Exemplo: middleware de autenticação que popula req.user
// com o tenantId do usuário autenticado.
function requireAuth(req, res, next) {
  // Em produção, valide aqui o JWT/sessão.
  // req.user = { id: "...", tenantId: "..." };

  if (!req.user) {
    return res.status(401).json({
      error: "Não autenticado",
    });
  }

  next();
}

app.delete("/api/users/:userId", requireAuth, async (req, res) => {
  const { userId } = req.params;
  const { tenantId } = req.user;

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `
      DELETE FROM users
      WHERE id = $1
        AND tenant_id = $2
      RETURNING id
      `,
      [userId, tenantId]
    );

    if (result.rowCount === 0) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "Usuário não encontrado neste tenant",
      });
    }

    await client.query("COMMIT");

    return res.status(200).json({
      success: true,
      message: "Usuário removido permanentemente",
      userId: result.rows[0].id,
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error("Erro ao remover usuário:", error);

    return res.status(500).json({
      error: "Não foi possível remover o usuário",
    });
  } finally {
    client.release();
  }
});

app.listen(3000, () => {
  console.log("API executando na porta 3000");
});
