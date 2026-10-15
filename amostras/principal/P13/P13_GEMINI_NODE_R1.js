import express from 'express';
import { PrismaClient } from '@prisma/client';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * GET /api/v1/customers
 * Lista os clientes do tenant autenticado com suporte a busca por nome e paginação.
 */
router.get('/customers', async (req, res) => {
  try {
    // 1. Identificação do Tenant (fornecido pelo middleware de autenticação/contexto)
    const tenantId = req.tenantId;

    if (!tenantId) {
      return res.status(401).json({ error: 'Tenant não identificado ou token inválido.' });
    }

    // 2. Extração dos parâmetros de query (filtro e paginação)
    const { name, page = 1, limit = 10 } = req.query;

    const pageNum = Math.max(1, parseInt(page, 10));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10))); // Limite máximo de 100 por página
    const skip = (pageNum - 1) * limitNum;

    // 3. Construção dinâmica das condições de busca (WHERE)
    const whereCondition = {
      tenantId: tenantId, // ISOLAMENTO MULTI-TENANT OBRIGATÓRIO
      ...(name && {
        name: {
          contains: String(name),
          mode: 'insensitive', // Busca case-insensitive
        },
      }),
    };

    // 4. Consulta ao banco de dados com contagem para paginação
    const [customers, totalItems] = await Promise.all([
      prisma.customer.findMany({
        where: whereCondition,
        select: {
          id: true,
          name: true,
          email: true,
          phone: true,
          createdAt: true,
        },
        orderBy: { name: 'asc' },
        skip,
        take: limitNum,
      }),
      prisma.customer.count({ where: whereCondition }),
    ]);

    // 5. Retorno formatado da API
    const totalPages = Math.ceil(totalItems / limitNum);

    return res.status(200).json({
      data: customers,
      meta: {
        totalItems,
        totalPages,
        currentPage: pageNum,
        itemsPerPage: limitNum,
      },
    });
  } catch (error) {
    console.error('Erro ao listar clientes:', error);
    return res.status(500).json({ error: 'Erro interno do servidor ao buscar clientes.' });
  }
});

export default router;