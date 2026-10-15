const express = require("express");
const router = express.Router();
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// GET /api/documents/search?q=contrato&type=pdf&authorId=123&from=2026-01-01&to=2026-12-31
router.get("/api/documents/search", async (req, res) => {
  const { q, type, authorId, from, to } = req.query;

  // tenantId deve vir do contexto autenticado, nunca do request.
  const tenantId = req.user.tenantId;

  if (!q || !q.trim()) {
    return res.status(400).json({
      error: "O parâmetro 'q' é obrigatório.",
    });
  }

  const conditions = [
    "d.tenant_id = $1",
    "to_tsvector('simple', coalesce(d.title, '') || ' ' || coalesce(d.content, '')) @@ plainto_tsquery('simple', $2)",
  ];

  const params = [tenantId, q.trim()];
  let index = 3;

  if (type) {
    conditions.push(`d.type = $${index++}`);
    params.push(type);
  }

  if (authorId) {
    conditions.push(`d.author_id = $${index++}`);
    params.push(authorId);
  }

  if (from) {
    conditions.push(`d.created_at >= $${index++}`);
    params.push(from);
  }

  if (to) {
    conditions.push(`d.created_at < ($${index++}::date + INTERVAL '1 day')`);
    params.push(to);
  }

  const sql = `
    SELECT
      d.id,
      d.title,
      d.type,
      d.author_id,
      d.created_at
    FROM documents d
    WHERE ${conditions.join(" AND ")}
    ORDER BY d.created_at DESC
    LIMIT 100
  `;

  try {
    const { rows } = await pool.query(sql, params);

    return res.json({
      data: rows,
      count: rows.length,
    });
  } catch (error) {
    console.error("Document search error:", error);
    return res.status(500).json({
      error: "Erro interno ao realizar a busca.",
    });
  }
});

module.exports = router;
