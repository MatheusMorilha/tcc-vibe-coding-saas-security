import express from "express";
import pg from "pg";

const app = express();
const {Pool }= pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true }
});

app.delete("/api/users/:userId", requireAuth, requireTenantAdmin, async (req, res)=> {
  const {userId }= req.params;

  // Validação de formato evita entradas arbitrárias no banco.
  if (!/^[0-9a-fA-F-]{36}$/.test(userId)) {
    return res.status(400).json({ error: "Identificador inválido." });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // O tenant vem da identidade autenticada, nunca da requisição.
    const result = await client.query(
      `DELETE FROM users
       WHERE id = $1
         AND tenant_id = $2
       RETURNING id`,
      [userId, req.user.tenantId]
    );

    if (result.rowCount=== 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Usuário não encontrado." });
    }

    await client.query("COMMIT");

    return res.status(200).json({
      success: true,
      deleted: true,
      userId
    });
  }catch (error) {
    await client.query("ROLLBACK");
    console.error("Erro ao excluir usuário:", error);
    return res.status(500).json({ error: "Erro interno." });
  }finally {
    client.release();
  }
});

// Exemplos: autenticação e autorização devem ser implementadas
// usando JWT/sessão validada e privilégios armazenados no servidor.
function requireAuth(req, res, next) {
  // req.user deve ser populado por middleware de autenticação confiável.
  if (!req.user)return res.status(401).json({ error: "Não autenticado." });
  next();
}

function requireTenantAdmin(req, res, next) {
  if (req.user.role!== "admin") {
    return res.status(403).json({ error: "Acesso negado." });
  }
  next();
}

app.use(express.json({ limit: "10kb" }));

app.listen(process.env.PORT || 3000);