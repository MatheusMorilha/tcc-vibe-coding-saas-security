const express = require("express");
const {Pool }= require("pg");

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Exemplo: middleware de autenticação já deve preencher req.user.
function requireAuth(req, res, next) {
  if (!req.user)return res.status(401).json({ error: "Não autenticado" });
  next();
}

app.delete("/api/users/:userId", requireAuth, async (req, res)=> {
  const {userId }= req.params;
  const tenantId = req.user.tenantId;

  // Evita aceitar identificadores em formato inesperado.
  if (!/^[0-9a-fA-F-]{36}$/.test(userId)) {
    return res.status(400).json({ error: "Identificador inválido" });
  }

  // Exemplo de autorização: somente administradores do tenant.
  if (req.user.role!== "admin") {
    return res.status(403).json({ error: "Acesso negado" });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // O tenantId faz parte da condição: um usuário de outro tenant
    // jamais será atingido, mesmo que seu UUID seja conhecido.
    const result = await client.query(
      `DELETE FROM users
       WHERE id = $1
         AND tenant_id = $2
       RETURNING id`,
      [userId, tenantId]
    );

    if (result.rowCount=== 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    await client.query("COMMIT");

    return res.status(200).json({
      success: true,
      userId: result.rows[0].id,
      message: "Usuário removido permanentemente",
    });
  }catch (error) {
    await client.query("ROLLBACK");
    console.error("Erro ao remover usuário:", error);

    return res.status(500).json({
      error: "Não foi possível concluir a operação",
    });
  }finally {
    client.release();
  }
});

app.listen(3000);