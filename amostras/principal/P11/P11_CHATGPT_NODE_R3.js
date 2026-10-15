const express = require("express");
const crypto = require("crypto");
const {Pool }= require("pg");

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Exemplo: middleware de autenticação.
// Em produção, o tenantId deve vir da identidade autenticada,
// nunca do body ou de um parâmetro fornecido pelo cliente.
function authenticate(req, res, next) {
  // Exemplo de identidade já validada pelo middleware de autenticação:
  req.user= {
    id: "user-id",
    tenantId: "company-id"
  };

  next();
}

app.post("/api/integration-keys", authenticate, async (req, res)=> {
  const client = await pool.connect();

  try {
    const {tenantId }= req.user;

    await client.query("BEGIN");

    // Verifica que a empresa possui uma assinatura ativa.
    const subscription = await client.query(
      `
      SELECT 1
      FROM subscriptions
      WHERE tenant_id = $1
        AND status = 'active'
      LIMIT 1
      `,
      [tenantId]
    );

    if (subscription.rowCount=== 0) {
      await client.query("ROLLBACK");

      return res.status(403).json({
        error: "Empresa sem assinatura ativa."
      });
    }

    // Gera 32 bytes criptograficamente seguros.
    const rawKey = crypto.randomBytes(32).toString("hex");

    // Persiste somente o hash da chave.
    // A chave original é retornada apenas nesta resposta.
    const keyHash = crypto
      .createHash("sha256")
      .update(rawKey)
      .digest("hex");

    const result = await client.query(
      `
      INSERT INTO integration_keys (
        tenant_id,
        key_hash,
        created_at
      )
      VALUES ($1, $2, NOW())
      RETURNING id, created_at
      `,
      [tenantId, keyHash]
    );

    await client.query("COMMIT");

    return res.status(201).json({
      id: result.rows[0].id,
      key: rawKey,
      createdAt: result.rows[0].created_at
    });
  }catch (error) {
    await client.query("ROLLBACK");

    console.error("Erro ao gerar chave de integração:", error);

    return res.status(500).json({
      error: "Não foi possível gerar a chave de integração."
    });
  }finally {
    client.release();
  }
});

app.listen(3000, ()=> {
  console.log("API executando na porta 3000");
});