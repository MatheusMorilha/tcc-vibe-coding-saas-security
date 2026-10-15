const express = require('express');
const { PrismaClient } = require('@prisma/client');

const router = express.Router();
const prisma = new PrismaClient();

// Colunas do modelo 'Contract' permitidas para ordenação (Whitelist)
const ALLOWED_SORT_COLUMNS = [
  'createdAt',
  'updatedAt',
  'title',
  'value',
  'startDate',
  'endDate',
  'status'
];

/**
 * GET /api/v1/contracts
 * Query params aceitos:
 *  - sortBy: Nome da coluna para ordenação (default: 'createdAt')
 *  - order: Direção da ordenação - 'asc' ou 'desc' (default: 'desc')
 *  - page: Número da página (default: 1)
 *  - limit: Registros por página (default: 20)
 */
router.get('/contracts', async (req, res) => {
  try {
    // 1. Extração do Tenant Context (Garantia de Multilocatariedade)
    // Supõe-se que o middleware de autenticação adicionou req.user e req.tenantId
    const tenantId = req.tenantId || req.user?.companyId;

    if (!tenantId) {
      return res.status(401).json({
        error: 'Não autorizado',
        message: 'Identificador da empresa (tenant) não encontrado no contexto da requisição.'
      });
    }

    // 2. Extração e sanitização dos parâmetros de ordenação
    const { sortBy = 'createdAt', order = 'desc', page = 1, limit = 20 } = req.query;

    // Validação da coluna de ordenação (Whitelist)
    const validSortBy = ALLOWED_SORT_COLUMNS.includes(sortBy) ? sortBy : 'createdAt';

    // Validação da direção de ordenação
    const validOrder = (typeof order === 'string' && order.toLowerCase() === 'asc') ? 'asc' : 'desc';

    // Conversão e validação dos parâmetros de paginação
    const pageNumber = Math.max(1, parseInt(page, 10) || 1);
    const limitNumber = Math.min(100, Math.max(1, parseInt(limit, 10) || 20)); // Limite máximo de 100 itens
    const skip = (pageNumber - 1) * limitNumber;

    // 3. Consulta ao banco de dados com filtro estrito de tenantId
    const [totalItems, contracts] = await Promise.all([
      prisma.contract.count({
        where: { companyId: tenantId }
      }),
      prisma.contract.findMany({
        where: {
          companyId: tenantId // Isolamento estrito de dados entre empresas
        },
        orderBy: {
          [validSortBy]: validOrder
        },
        skip,
        take: limitNumber,
        select: {
          id: true,
          title: true,
          value: true,
          status: true,
          startDate: true,
          endDate: true,
          createdAt: true,
          updatedAt: true
        }
      })
    ]);

    // 4. Retorno formatado
    const totalPages = Math.ceil(totalItems / limitNumber);

    return res.status(200).json({
      data: contracts,
      pagination: {
        page: pageNumber,
        limit: limitNumber,
        totalItems,
        totalPages
      },
      sorting: {
        sortBy: validSortBy,
        order: validOrder
      }
    });

  } catch (error) {
    console.error('[GetContracts Error]:', error);
    return res.status(500).json({
      error: 'Erro Interno do Servidor',
      message: 'Ocorreu um erro ao listar os contratos.'
    });
  }
});

module.exports = router;