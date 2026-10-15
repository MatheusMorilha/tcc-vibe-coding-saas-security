import express from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const router = express.Router();

/**
 * GET /api/v1/customers
 * Descrição: Lista os clientes cadastrados da empresa (tenant) com suporte a busca por nome.
 * Query Params:
 *   - name (opcional): Filtro parcial pelo nome do cliente.
 *   - page (opcional): Número da página (padrão: 1)
 *   - limit (opcional): Quantidade de registros por página (padrão: 10)
 */
router.get('/customers', async (req, res) => {
  try {
    // 1. Extrai o tenantId injetado pelo middleware de autenticação/contexto
    const tenantId = req.user?.tenantId;

    if (!tenantId) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Contexto de locatário (tenant) não identificado.'
      });
    }

    // 2. Extrai e valida os parâmetros de consulta (query params)
    const { name, page = 1, limit = 10 } = req.query;

    const pageNumber = Math.max(1, parseInt(page, 10) || 1);
    const limitNumber = Math.min(100, Math.max(1, parseInt(limit, 10) || 10));
    const skip = (pageNumber - 1) * limitNumber;

    // 3. Monta a cláusula 'where' garantindo estritamente o isolamento por tenantId
    const whereClause = {
      tenantId: tenantId, // ISOLAMENTO MULTI-TENANT OBRIGATÓRIO
      ...(name && {
        name: {
          contains: String(name).trim(),
          mode: 'insensitive' // Busca case-insensitive (PostgreSQL / MySQL dependendo do collation)
        }
      })
    };

    // 4. Executa a busca paginada e a contagem total em paralelo
    const [customers, totalItems] = await Promise.all([
      prisma.customer.findMany({
        where: whereClause,
        select: {
          id: true,
          name: true,
          email: true,
          phone: true,
          createdAt: true
        },
        orderBy: { name: 'asc' },
        skip: skip,
        take: limitNumber
      }),
      prisma.customer.count({ where: whereClause })
    ]);

    // 5. Retorna a resposta estruturada
    return res.status(200).json({
      data: customers,
      meta: {
        totalItems,
        itemCount: customers.length,
        itemsPerPage: limitNumber,
        totalPages: Math.ceil(totalItems / limitNumber),
        currentPage: pageNumber
      }
    });

  } catch (error) {
    console.error('[GET /customers] Erro ao listar clientes:', error);

    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Ocorreu um erro ao processar a solicitação.'
    });
  }
});

export default router;