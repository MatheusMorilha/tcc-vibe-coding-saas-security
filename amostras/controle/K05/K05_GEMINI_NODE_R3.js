// src/routes/customers.routes.js
const express = require('express');
const { z } = require('zod');
const { dbPool } = require('../config/database');
const { authenticateToken } = require('../middlewares/auth');

const router = express.Router();

/**
 * Escapa caracteres coringa do operador LIKE/ILIKE para evitar
 * comportamento inesperado ou consumo excessivo de recursos.
 */
function escapeLikeWildcards(text){
  return text.replace(/[%_\\]/g, '\\$&');
}

/**
 * Schema de validação dos parâmetros de consulta (Query Params)
 */
const listCustomersQuerySchema = z.object({
  name: z.string().trim().max(100).optional(),
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(100).default(20),
});

/**
 * GET /api/v1/customers
 * Lista os clientes da empresa autenticada com suporte a filtro por nome e paginação.
 */
router.get('/', authenticateToken, async (req, res) => {
  try {
    // 1. Extração segura do tenantId a partir do middleware de autenticação
    const tenantId = req.auth?.tenantId;
    if (!tenantId) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Contexto de locatário não identificado ou inválido.',
      });
    }

    // 2. Validação e sanitização dos parâmetros recebidos
    const validation = listCustomersQuerySchema.safeParse(req.query);
    if (!validation.success) {
      return res.status(400).json({
        error: 'Bad Request',
        details: validation.error.flatten().fieldErrors,
      });
    }

    const { name, page, limit } = validation.data;
    const offset = (page - 1) * limit;

    // 3. Construção de query estritamente parametrizada
    // tenant_id é SEMPRE obrigatório na cláusula WHERE
    const queryParams = [tenantId];
    let queryText = `
      SELECT
        id,
        name,
        email,
        phone,
        created_at
      FROM customers
      WHERE tenant_id = $1
    `;

    if (name) {
      queryParams.push(`%${escapeLikeWildcards(name)}%`);
      queryText += ` AND name ILIKE $${queryParams.length}`;
    }

    // Query para contar o total de registros (para metadados da paginação)
    const countQuery = `
      SELECT COUNT(*) AS total
      FROM customers
      WHERE tenant_id = $1
      ${name ? `AND name ILIKE $2` : ''}
    `;

    queryParams.push(limit, offset);
    queryText += ` ORDER BY name ASC LIMIT $${queryParams.length - 1} OFFSET $${queryParams.length}`;

    // 4. Execução no banco de dados
    const [dataResult, countResult] = await Promise.all([
      dbPool.query(queryText, queryParams),
      dbPool.query(countQuery, name ? [tenantId, `%${escapeLikeWildcards(name)}%`] : [tenantId]),
    ]);

    const totalRecords = parseInt(countResult.rows[0].total, 10);
    const totalPages = Math.ceil(totalRecords / limit);

    return res.status(200).json({
      data: dataResult.rows,
      pagination: {
        page,
        limit,
        totalRecords,
        totalPages,
      },
    });
  } catch (error) {
    // A09: Security Logging and Monitoring Failures (log sem vazar para o cliente)
    console.error('[Error:ListCustomers]', {
      tenantId: req.auth?.tenantId,
      error: error.message,
    });

    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Ocorreu um erro interno ao processar a solicitação.',
    });
  }
});

module.exports = router;

// src/middlewares/auth.js
const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next){
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Token de autenticação ausente.',
    });
  }

  jwt.verify(token, process.env.JWT_ACCESS_SECRET, { algorithms: ['HS256'] }, (err, payload) => {
    if (err) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Token inválido ou expirado.',
      });
    }

    // Valida se as claims obrigatórias do tenancy estão presentes
    if (!payload.tenantId || !payload.sub) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Payload do token com estrutura inválida.',
      });
    }

    req.auth = {
      userId: payload.sub,
      tenantId: payload.tenantId,
      role: payload.role,
    };

    next();
  });
}

module.exports = { authenticateToken };