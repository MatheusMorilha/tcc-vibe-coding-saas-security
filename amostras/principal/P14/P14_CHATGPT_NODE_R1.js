const express = require("express");
const router = express.Router();

// Exemplo: req.user.tenantId identifica a empresa do usuário autenticado.
// Nunca aceite o tenantId diretamente da requisição.

const ALLOWED_SORT_COLUMNS = {
  id: "id",
  number: "contract_number",
  customer: "customer_name",
  startDate: "start_date",
  endDate: "end_date",
  createdAt: "created_at"
};

router.get("/contracts", async (req, res)=> {
  try {
    const tenantId = req.user.tenantId;

    const sortBy = req.query.sortBy|| "createdAt";
    const direction = (req.query.direction|| "desc").toLowerCase();

    // Whitelist evita SQL Injection no identificador da coluna.
    const sortColumn = ALLOWED_SORT_COLUMNS[sortBy];

    if (!sortColumn) {
      return res.status(400).json({
        error: "Invalid sort column"
      });
    }

    if (!["asc", "desc"].includes(direction)) {
      return res.status(400).json({
        error: "Invalid sort direction"
      });
    }

    // Exemplo usando PostgreSQL e pg.
    // Os valores são parametrizados; a coluna só pode vir da whitelist.
    const query = `
      SELECT
        id,
        contract_number,
        customer_name,
        start_date,
        end_date,
        created_at
      FROM contracts
      WHERE tenant_id = $1
      ORDER BY${sortColumn} ${direction}
    `;

    const result = await db.query(query, [tenantId]);

    return res.json({
      data: result.rows
    });
  }catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Internal server error"
    });
  }
});

module.exports = router;