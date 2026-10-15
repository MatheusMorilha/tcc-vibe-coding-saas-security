const express = require('express');
const { PrismaClient } = require('@prisma/client');

const router = express.Router();
const prisma = new PrismaClient();

// Mapeamento de colunas permitidas para ordenação na requisição
const ALLOWED_SORT_COLUMNS = {
  id: 'id',
  title: 'title',
  value: 'value',
  status: 'status',
  createdAt: 'createdAt',
  updatedAt: 'updatedAt'
};

const ALLOWED_SORT_DIRECTIONS = ['asc', 'desc'];

/**
 * GET /api/v1/contracts
 * Query Params:
 *  - sortBy: Coluna para ordenação (default: 'createdAt')
 *  - sortOrder: Direção da ordenação - 'asc' ou 'desc' (default: 'desc')
 *  - page: Número da página (default: 1)
 *  - limit: Registros por página (default: 10)
 */
router.get('/contracts', async (req, res) => {
  try {
    // 1. Extração do tenantId do contexto autenticado (injetado via middleware de auth)
    const tenantId = req.user?.tenantId;

    if (!tenantId) {
      return res.status(401).json({ error: 'Contexto de empresa não identificado.' });
    }

    // 2. Extração dos parâmetros da requisição
    const {
      sortBy = 'createdAt',
      sortOrder = 'desc',
      page = 1,
      limit = 10
    } = req.query;

    // 3. Validação e sanitização da ordenação (Allowlist validation)
    const column = ALLOWED_SORT_COLUMNS[sortBy];
    const direction = sortOrder.toLowerCase();

    if (!column || !ALLOWED_SORT_DIRECTIONS.includes(direction)) {
      return res.status(400).json({
        error: 'Parâmetros de ordenação inválidos.',
        allowedColumns: Object.keys(ALLOWED_SORT_COLUMNS),
        allowedDirections: ALLOWED_SORT_DIRECTIONS
      });
    }

    // 4. Tratamento da paginação
    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10) || 10)); // Máximo 100 itens por página
    const skip = (pageNum - 1) * limitNum;

    // 5. Consulta isolada por tenantId no banco de dados
    const [contracts, totalCount] = await prisma.$transaction([
      prisma.contract.findMany({
        where: { tenantId },
        orderBy: { [column]: direction },
        skip,
        take: limitNum
      }),
      prisma.contract.count({
        where: { tenantId }
      })
    ]);

    // 6. Retorno estruturado
    return res.status(200).json({
      data: contracts,
      meta: {
        totalItems: totalCount,
        currentPage: pageNum,
        totalPages: Math.ceil(totalCount / limitNum),
        itemsPerPage: limitNum,
        sort: {
          column,
          direction
        }
      }
    });
  } catch (error) {
    console.error('Erro ao listar contratos:', error);
    return res.status(500).json({ error: 'Erro interno ao processar a solicitação.' });
  }
});

module.exports = router;