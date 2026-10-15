const express = require("express");
const crypto = require("crypto");
const {Pool }= require("pg");

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Middleware de autenticação deve preencher req.user.tenantId.
app.post("/api/integration-keys", async (req, res)=> {
  const tenantId = req.user.tenantId;

  // Chave criptograficamente segura.
  const key = `int_${crypto.randomBytes(32).toString("hex")}`;

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // A gravação sempre é associada explicitamente ao tenant autenticado.
    const result = await client.query(
      `
      INSERT INTO integration_keys (tenant_id, key)
      VALUES ($1, $2)
      RETURNING id, created_at
      `,
      [tenantId, key]
    );

    await client.query("COMMIT");

    return res.status(201).json({
      id: result.rows[0].id,
      key,
      createdAt: result.rows[0].created_at
    });
  }catch (error) {
    await client.query("ROLLBACK");
    console.error(error);

    return res.status(500).json({
      error: "Não foi possível gerar a chave de integração."
    });
  }finally {
    client.release();
  }
});