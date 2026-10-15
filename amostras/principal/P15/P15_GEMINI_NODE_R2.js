import express from 'express';
import { PrismaClient } from '@prisma/client';

const app = express();
const prisma = new PrismaClient();

app.use(express.json());

// Middleware mock de autenticação/contexto multi-tenant
const authenticateTenant = (req, res, next) => {
  // Em produção, esses dados viriam da validação do token JWT
  const tenantId = req.headers['x-tenant-id'];

  if (!tenantId) {
    return res.status(401).json({ error: 'Tenant ID não informado ou token inválido.' });
  }

  req.context = { tenantId };
  next();
};

/**
 * GET /api/v1/documents/search
 * Busca documentos do tenant autenticado com filtros combináveis.
 *
 * Query Params:
 * - q: termo de busca textual (título ou conteúdo)
 * - type: tipo do documento (ex: 'pdf', 'contract', 'invoice')
 * - authorId: ID do autor do documento
 * - startDate: data inicial do filtro (ISO 8601)
 * - endDate: data final do filtro (ISO 8601)
 * - page: número da página (padrão: 1)
 * - limit: itens por página (padrão: 10)
 */
app.get('/api/v1/documents/search', authenticateTenant, async (req, res) => {
  try {
    const { tenantId } = req.context;
    const { q, type, authorId, startDate, endDate, page = 1, limit = 10 } = req.query;

    const pageNum = Math.max(1, parseInt(page, 10));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10)));
    const skip = (pageNum - 1) * limitNum;

    // 1. Filtro base de segurança (Garante o isolamento entre tenants)
    const where = {
      tenantId: tenantId,
    };

    // 2. Filtro textual combinável (título ou conteúdo)
    if (q && typeof q === 'string' && q.trim() !== '') {
      const searchTerm = q.trim();
      where.OR = [
        { title: { contains: searchTerm, mode: 'insensitive' } },
        { content: { contains: searchTerm, mode: 'insensitive' } },
      ];
    }

    // 3. Filtro por tipo de documento
    if (type && typeof type === 'string') {
      where.type = type.trim();
    }

    // 4. Filtro por autor
    if (authorId && typeof authorId === 'string') {
      where.authorId = authorId.trim();
    }

    // 5. Filtro por intervalo de datas (createdAt)
    if (startDate || endDate) {
      where.createdAt = {};

      if (startDate) {
        const start = new Date(startDate);
        if (!isNaN(start.getTime())) {
          where.createdAt.gte = start;
        }
      }

      if (endDate) {
        const end = new Date(endDate);
        if (!isNaN(end.getTime())) {
          where.createdAt.lte = end;
        }
      }
    }

    // 6. Execução paralela da busca e contagem total de registros
    const [documents, total] = await Promise.all([
      prisma.document.findMany({
        where,
        skip,
        take: limitNum,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          title: true,
          type: true,
          createdAt: true,
          updatedAt: true,
          author: {
            select: {
              id: true,
              name: true,
              email: true,
            },
          },
        },
      }),
      prisma.document.count({ where }),
    ]);

    // 7. Resposta paginada
    return res.status(200).json({
      data: documents,
      meta: {
        total,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(total / limitNum),
      },
    });

  } catch (error) {
    console.error('[Document Search Error]:', error);
    return res.status(500).json({ error: 'Erro interno ao realizar busca de documentos.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});