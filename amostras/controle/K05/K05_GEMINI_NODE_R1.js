// routes/clients.js
import express from 'express';
import { z } from 'zod';
import { pool } from '../db.js'; // Conexão com postgres (pg)
import { authenticateToken } from '../middlewares/auth.js';

const router = express.Router();

// Schema de validação dos parâmetros de consulta (OWASP A03 / Input Validation)
const listClientsQuerySchema = z.object({
  name: z.string().trim().max(100).optional(),
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(50).default(20),
});

/**
 * GET /api/v1/clients
 * Lista os clientes do tenant autenticado com filtro opcional por nome.
 */
router.get('/clients', authenticateToken, async (req, res) => {
  // 1. Extração segura do tenantId a partir do token validado no middleware
  const tenantId = req.user?.tenantId;
  if (!tenantId) {
    return res.status(403).json({ error: 'Acesso negado: Locatário não identificado.' });
  }

  // 2. Validação e sanitização dos parâmetros de entrada
  const parsed = listClientsQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    return res.status(400).json({
      error: 'Parâmetros de consulta inválidos.',
      details: parsed.error.issues.map((issue) => issue.message),
    });
  }

  const { name, page, limit } = parsed.data;
  const offset = (page - 1) * limit;

  // 3. Montagem segura da consulta com parâmetros posicionais ($1, $2, ...)
  const queryParams = [tenantId];
  let whereClauses = 'WHERE tenant_id = $1 AND deleted_at IS NULL';

  if (name) {
    // Escapa caracteres especiais de wildcard do LIKE se necessário
    const sanitizedSearch = name.replace(/[%_]/g, '\\$&');
    queryParams.push(`%${sanitizedSearch}%`);
    whereClauses += ` AND name ILIKE $${queryParams.length}`;
  }

  // Paginação controlada
  queryParams.push(limit, offset);
  const paginationClauses = ` ORDER BY created_at DESC LIMIT $${queryParams.length - 1} OFFSET $${queryParams.length}`;

  const sqlQuery = `
    SELECT
      id,
      name,
      document,
      email,
      phone,
      created_at
    FROM clients
    ${whereClauses}
    ${paginationClauses};
  `;

  try {
    const { rows } = await pool.query(sqlQuery, queryParams);

    return res.status(200).json({
      data: rows,
      pagination: {
        page,
        limit,
        count: rows.length,
      },
    });
  } catch (error) {
    // Log detalhado interno; resposta genérica ao cliente (OWASP A09)
    console.error(`[DB_ERROR] Falha ao listar clientes para o tenant ${tenantId}:`, error);
    return res.status(500).json({ error: 'Erro interno ao processar a requisição.' });
  }
});

export default router;

// middlewares/auth.js
import jwt from 'jsonwebtoken';

export function authenticateToken(req, res, next){
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de autenticação ausente.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido ou expirado.' });
    }

    // decoded deve conter { userId: string, tenantId: string, role: string }
    req.user = decoded;
    next();
  });
}