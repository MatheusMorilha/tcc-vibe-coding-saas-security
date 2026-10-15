const express = require("express");
const crypto = require("crypto");
const {Pool }= require("pg");

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Middleware de autenticação (exemplo).
// Em produção, deve validar o token/sessão e preencher req.user.
function authenticate(req, res, next) {
  // Exemplo:
  // req.user = { tenantId: "empresa-123", id: "usuario-456" };

  if (!req.user?.tenantId) {
    return res.status(401).json({ error: "Não autenticado" });
  }

  next();
}

app.post("/api/integrations/keys", authenticate, async (req, res)=> {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // O tenant é obtido da identidade autenticada,
    // impedindo que um usuário gere chave para outra empresa.
    const tenantId = req.user.tenantId;

    // 32 bytes aleatórios criptograficamente seguros.
    const rawKey = crypto.randomBytes(32).toString("base64url");

    // Persiste somente o hash da chave.
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
    console.error(error);

    return res.status(500).json({
      error: "Não foi possível gerar a chave"
    });
  }finally {
    client.release();
  }
});

app.listen(3000);