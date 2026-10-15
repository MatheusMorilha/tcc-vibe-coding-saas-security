const express = require('express');
const router = express.Router();
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Middleware de autenticação fictício (deve preencher req.user com o tenantId do usuário logado)
const { authenticateToken } = require('../middlewares/auth');

/**
 * GET /api/v1/tenants/:tenantId/reports/financial
 * Retorna o relatório financeiro consolidado do período informado.
 *
 * Query Params:
 * - startDate: ISO Date string (ex: 2026-01-01)
 * - endDate:   ISO Date string (ex: 2026-01-31)
 */
router.get('/tenants/:tenantId/reports/financial', authenticateToken, async (req, res) => {
  try {
    const { tenantId } = req.params;
    const { startDate, endDate } = req.query;

    // 1. Validação de Isolamento de Tenant (Multitenancy Check)
    if (req.user.tenantId !== tenantId) {
      return res.status(403).json({
        code: 'FORBIDDEN_TENANT_ACCESS',
        message: 'Acesso negado aos dados desta empresa.'
      });
    }

    // 2. Validação básica de parâmetros de data
    if (!startDate || !endDate) {
      return res.status(400).json({
        code: 'MISSING_PERIOD_PARAMS',
        message: 'Os parâmetros startDate e endDate são obrigatórios.'
      });
    }

    const start = new Date(startDate);
    const end = new Date(endDate);

    if (isNaN(start.getTime()) || isNaN(end.getTime()) || start > end) {
      return res.status(400).json({
        code: 'INVALID_DATE_RANGE',
        message: 'Período de datas inválido ou inconsistente.'
      });
    }

    // Ajusta o final do dia para cobrir todo o período informado (23:59:59.999)
    end.setUTCHours(23, 59, 59, 999);

    // 3. Execução paralela de agregação no Banco de Dados
    const [incomeAggregate, expenseAggregate, statusBreakdown] = await Promise.all([
      // Somatório de Receitas (ENTRADA) no período
      prisma.transaction.aggregate({
        _sum: { amount: true },
        where: {
          tenantId: tenantId,
          type: 'INCOME',
          dueDate: { gte: start, lte: end }
        }
      }),

      // Somatório de Despesas (SAIDA) no período
      prisma.transaction.aggregate({
        _sum: { amount: true },
        where: {
          tenantId: tenantId,
          type: 'EXPENSE',
          dueDate: { gte: start, lte: end }
        }
      }),

      // Agrupamento por status (PAID, PENDING, OVERDUE)
      prisma.transaction.groupBy({
        by: ['status'],
        _sum: { amount: true },
        _count: { id: true },
        where: {
          tenantId: tenantId,
          dueDate: { gte: start, lte: end }
        }
      })
    ]);

    // 4. Consolidação do Balanço Financeiro
    const totalIncome = Number(incomeAggregate._sum.amount || 0);
    const totalExpense = Number(expenseAggregate._sum.amount || 0);
    const netBalance = totalIncome - totalExpense;

    const summaryByStatus = statusBreakdown.reduce((acc, curr) => {
      acc[curr.status] = {
        totalAmount: Number(curr._sum.amount || 0),
        transactionCount: curr._count.id
      };
      return acc;
    }, {});

    // 5. Retorno Consolidado
    return res.status(200).json({
      meta: {
        tenantId,
        period: {
          startDate: start.toISOString(),
          endDate: end.toISOString()
        },
        generatedAt: new Date().toISOString()
      },
      data: {
        summary: {
          totalIncome,
          totalExpense,
          netBalance
        },
        statusBreakdown: {
          PAID: summaryByStatus.PAID || { totalAmount: 0, transactionCount: 0 },
          PENDING: summaryByStatus.PENDING || { totalAmount: 0, transactionCount: 0 },
          OVERDUE: summaryByStatus.OVERDUE || { totalAmount: 0, transactionCount: 0 }
        }
      }
    });

  } catch (error) {
    console.error('[Financial Report Error]:', error);
    return res.status(500).json({
      code: 'INTERNAL_SERVER_ERROR',
      message: 'Ocorreu um erro ao processar o relatório financeiro.'
    });
  }
});

module.exports = router;