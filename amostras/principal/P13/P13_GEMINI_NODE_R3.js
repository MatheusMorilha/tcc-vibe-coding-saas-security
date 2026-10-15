const express = require('express');
const router = express.Router();
const db = require('../db'); // Instância do Pool do pg/Knex/ORM

/**
 * GET /api/v1/customers
 * Lista os clientes do tenant autenticado, com suporte a busca por nome e paginação.
 */
router.get('/customers', async (req, res) => {
  try {
    // 1. Extrai o ID do tenant (definido no middleware de autenticação/JWT)
    const tenantId = req.user?.tenantId;
    if (!tenantId) {
      return res.status(401).json({ error: 'Tenant não identificado ou não autenticado.' });
    }

    // 2. Query params para filtro e paginação
    const { name, page = 1, limit = 10 } = req.query;
    const pageNum = Math.max(1, parseInt(page, 10));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10)));
    const offset = (pageNum - 1) * limitNum;

    // 3. Construção dinâmica do filtro de busca por nome
    let nameFilter = '';
    const queryParams = [tenantId];

    if (name && name.trim() !== '') {
      queryParams.push(`%${name.trim()}%`);
      nameFilter = `AND name ILIKE $${queryParams.length}`; // ILIKE para busca case-insensitive no PostgreSQL
    }

    // 4. Query para contar o total de registros (para metadados de paginação)
    const countQuery = `
      SELECT COUNT(*) AS total
      FROM customers
      WHERE tenant_id = $1 ${nameFilter};
    `;
    const countResult = await db.query(countQuery, queryParams);
    const totalRecords = parseInt(countResult.rows[0].total, 10);

    // 5. Query principal parametrizada
    queryParams.push(limitNum, offset);
    const dataQuery = `
      SELECT id, name, email, phone, status, created_at
      FROM customers
      WHERE tenant_id = $1 ${nameFilter}
      ORDER BY name ASC
      LIMIT $${queryParams.length - 1} OFFSET $${queryParams.length};
    `;

    const { rows: customers } = await db.query(dataQuery, queryParams);

    // 6. Resposta paginada
    return res.status(200).json({
      data: customers,
      pagination: {
        page: pageNum,
        limit: limitNum,
        totalRecords,
        totalPages: Math.ceil(totalRecords / limitNum)
      }
    });

  } catch (error) {
    console.error('Erro ao listar clientes:', error);
    return res.status(500).json({ error: 'Erro interno ao buscar clientes.' });
  }
});

module.exports = router;