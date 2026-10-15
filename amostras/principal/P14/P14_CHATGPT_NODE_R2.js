const express = require("express");
const app = express();

const ALLOWED_SORT_COLUMNS = {
  id: "id",
  name: "name",
  createdAt: "created_at",
  expiresAt: "expires_at"
};

app.get("/contracts", async (req, res) => {
  const tenantId = req.user.companyId;

  const sortColumn =
    ALLOWED_SORT_COLUMNS[req.query.sortBy] || "created_at";

  const direction =
    String(req.query.order || "asc").toLowerCase() === "desc"
      ? "DESC"
      : "ASC";

  const sql = `
    SELECT id, name, created_at, expires_at
    FROM contracts
    WHERE company_id = $1
    ORDER BY ${sortColumn} ${direction}
  `;

  try {
    const result = await db.query(sql, [tenantId]);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Erro ao listar contratos" });
  }
});

app.listen(3000);
