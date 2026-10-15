const express = require('express');
const router = express.Router();
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

/**
 * GET /api/v1/companies/:companyId/reports/financial
 * Retorna o relatório financeiro consolidado de uma empresa para um determinado período.
 *
 * Query Params:
 * - startDate (ISO String: YYYY-MM-DD)
 * - endDate (ISO String: YYYY-MM-DD)
 */
router.get('/companies/:companyId/reports/financial', async (req, res) => {
  try {
    const { companyId } = req.params;
    const { startDate, endDate } = req.query;

    // 1. Validação dos parâmetros obrigatórios
    if (!startDate || !endDate) {
      return res.status(400).json({
        error: 'BadRequest',
        message: 'Os parâmetros "startDate" e "endDate" são obrigatórios.'
      });
    }

    const start = new Date(startDate);
    const end = new Date(endDate);
    end.setHours(23, 59, 59, 999); // Ajusta para o final do dia de término

    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      return res.status(400).json({
        error: 'BadRequest',
        message: 'Datas inválidas fornecidas. Utilizar o formato YYYY-MM-DD.'
      });
    }

    // 2. Validação Multi-tenant & Autorização (Cross-Tenant Security Check)
    // O tenant autenticado via token/sessão DEVE coincidir com o tenant solicitado na URL
    if (req.user.companyId !== companyId) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Acesso negado: Você não possui permissão para acessar os dados desta empresa.'
      });
    }

    // 3. Verificação de Assinatura Ativa do Tenant
    const company = await prisma.company.findUnique({
      where: { id: companyId },
      select: { id: true, subscriptionStatus: true }
    });

    if (!company) {
      return res.status(404).json({
        error: 'NotFound',
        message: 'Empresa cliente não encontrada.'
      });
    }

    if (company.subscriptionStatus !== 'ACTIVE') {
      return res.status(402).json({
        error: 'PaymentRequired',
        message: 'A assinatura da empresa está inativa ou suspensa.'
      });
    }

    // 4. Consulta e Agregação de Dados isolados por companyId
    const [summary, transactionsByCategory] = await Promise.all([
      // Totais consolidados de Entradas e Saídas
      prisma.transaction.groupBy({
        by: ['type'],
        where: {
          companyId: companyId, // Garante o isolamento do tenant no banco
          date: {
            gte: start,
            lte: end
          },
          status: 'PAID' // Apenas transações quitadas
        },
        _sum: {
          amount: true
        }
      }),

      // Detalhamento consolidado por Categoria
      prisma.transaction.groupBy({
        by: ['categoryId', 'type'],
        where: {
          companyId: companyId,
          date: {
            gte: start,
            lte: end
          },
          status: 'PAID'
        },
        _sum: {
          amount: true
        }
      })
    ]);

    // 5. Formatação do Resultado Consolidado
    let totalRevenue = 0;
    let totalExpenses = 0;

    summary.forEach((group) => {
      if (group.type === 'INCOME') totalRevenue = group._sum.amount || 0;
      if (group.type === 'EXPENSE') totalExpenses = group._sum.amount || 0;
    });

    const netProfit = totalRevenue - totalExpenses;

    return res.status(200).json({
      meta: {
        companyId,
        period: {
          startDate,
          endDate
        },
        generatedAt: new Date().toISOString()
      },
      summary: {
        totalRevenue,
        totalExpenses,
        netProfit,
        profitMargin: totalRevenue > 0 ? Number(((netProfit / totalRevenue) * 100).toFixed(2)) : 0
      },
      categoriesBreakdown: transactionsByCategory.map((item) => ({
        categoryId: item.categoryId,
        type: item.type,
        totalAmount: item._sum.amount || 0
      }))
    });

  } catch (error) {
    console.error(`Error generating financial report for tenant ${req.params.companyId}:`, error);
    return res.status(500).json({
      error: 'InternalServerError',
      message: 'Ocorreu um erro interno ao gerar o relatório financeiro.'
    });
  }
});

module.exports = router;