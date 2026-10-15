const express = require('express');
const { PrismaClient } = require('@prisma/client');

const router = express.Router();
const prisma = new PrismaClient();

// Colunas permitidas para ordenação (Evita SQL Injection/erros de coluna inexistente)
const ALLOWED_SORT_COLUMNS = {
  id: 'id',
  title: 'title',
  value: 'value',
  status: 'status',
  startDate: 'startDate',
  endDate: 'endDate',
  createdAt: 'createdAt',
  updatedAt: 'updatedAt'
};

/**
 * GET /api/v1/contracts
 * Query params:
 *   - sortBy: nome da coluna (default: 'createdAt')
 *   - sortOrder: 'asc' ou 'desc' (default: 'desc')
 */
router.get('/contracts', async (req, res) => {
  try {
    // 1. Garantir o Multitenancy: Obtém o tenantId do usuário autenticado no middleware/contexto
    const tenantId = req.user?.companyId;

    if (!tenantId) {
      return res.status(401).json({
        error: 'Não autorizado',
        message: 'Identificador do locatário (companyId) não encontrado no contexto da requisição.'
      });
    }

    // 2. Extração e Validação dos parâmetros de ordenação
    const { sortBy = 'createdAt', sortOrder = 'desc' } = req.query;

    // Normaliza e valida a direção da ordenação
    const normalizedOrder = String(sortOrder).toLowerCase() === 'asc' ? 'asc' : 'desc';

    // Valida a coluna solicitada contra a lista de permissões (whitelist)
    const normalizedSortBy = ALLOWED_SORT_COLUMNS[sortBy];

    if (!normalizedSortBy) {
      return res.status(400).json({
        error: 'Parâmetro inválido',
        message: `A coluna '${sortBy}' não é válida para ordenação. Colunas permitidas: ${Object.keys(ALLOWED_SORT_COLUMNS).join(', ')}`
      });
    }

    // 3. Consulta ao Banco de Dados com escopo estrito por Tenant
    const contracts = await prisma.contract.findMany({
      where: {
        companyId: tenantId // <--- Garantia de isolamento entre empresas
      },
      orderBy: {
        [normalizedSortBy]: normalizedOrder
      },
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
    });

    // 4. Resposta com metadados da consulta
    return res.status(200).json({
      data: contracts,
      meta: {
        total: contracts.length,
        sortBy: normalizedSortBy,
        sortOrder: normalizedOrder
      }
    });

  } catch (error) {
    console.error('[GET /contracts Error]:', error);
    return res.status(500).json({
      error: 'Erro interno do servidor',
      message: 'Não foi possível listar os contratos no momento.'
    });
  }
});

module.exports = router;