import express from 'express';
import { PrismaClient } from '@prisma/client';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * Helper para validar formato de datas YYYY-MM-DD
 */
function isValidDate(dateString){
  const regEx = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateString.match(regEx)) return false;
  const d = new Date(dateString);
  const dNum = d.getTime();
  if (!dNum && dNum !== 0) return false;
  return d.toISOString().slice(0, 10) === dateString;
}

/**
 * POST /api/v1/reports/financial
 * Gera relatório financeiro consolidado por empresa e período
 */
router.post('/reports/financial', async (req, res) => {
  try {
    const { companyId, startDate, endDate } = req.body;

    // 1. Validação de Parâmetros de Entrada
    if (!companyId || !startDate || !endDate) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Os parâmetros companyId, startDate e endDate são obrigatórios.'
      });
    }

    if (!isValidDate(startDate) || !isValidDate(endDate)) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'As datas devem estar no formato YYYY-MM-DD.'
      });
    }

    const start = new Date(`${startDate}T00:00:00.000Z`);
    const end = new Date(`${endDate}T23:59:59.999Z`);

    if (start > end) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'A data inicial (startDate) não pode ser maior que a data final (endDate).'
      });
    }

    // 2. Segurança Multi-tenant (Contexto do Usuário Autenticado)
    // Assume-se middleware prévio de autenticação inserindo req.user
    const authenticatedUser = req.user;
    if (!authenticatedUser || authenticatedUser.companyId !== companyId) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Acesso negado aos dados desta empresa.'
      });
    }

    // 3. Validação do Status da Assinatura da Empresa
    const company = await prisma.company.findUnique({
      where: { id: companyId },
      select: { id: true, name: true, subscriptionStatus: true }
    });

    if (!company) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Empresa não encontrada.'
      });
    }

    if (company.subscriptionStatus !== 'ACTIVE') {
      return res.status(402).json({
        error: 'Payment Required',
        message: 'Assinatura inativa ou suspensa. Regularize o plano para acessar relatórios.'
      });
    }

    // 4. Agregação no Banco de Dados (Isolamento rígido por companyId)
    const metrics = await prisma.financialTransaction.groupBy({
      by: ['type'],
      where: {
        companyId: companyId, // Filtro Multi-tenant vital
        status: 'PAID',       // Apenas transações liquidadas
        dueDate: {
          gte: start,
          lte: end
        }
      },
      _sum: {
        amount: true
      },
      _count: {
        id: true
      }
    });

    // 5. Consolidação dos Resultados
    let totalRevenue = 0;
    let totalExpense = 0;
    let revenueCount = 0;
    let expenseCount = 0;

    metrics.forEach(group => {
      const sum = Number(group._sum.amount || 0);
      if (group.type === 'INCOME') {
        totalRevenue = sum;
        revenueCount = group._count.id;
      } else if (group.type === 'EXPENSE') {
        totalExpense = sum;
        expenseCount = group._count.id;
      }
    });

    const netProfit = totalRevenue - totalExpense;

    // 6. Retorno Consolidado
    return res.status(200).json({
      meta: {
        companyId: company.id,
        companyName: company.name,
        period: {
          startDate,
          endDate
        },
        generatedAt: new Date().toISOString()
      },
      summary: {
        totalRevenue: Number(totalRevenue.toFixed(2)),
        totalExpense: Number(totalExpense.toFixed(2)),
        netProfit: Number(netProfit.toFixed(2)),
        transactionCounts: {
          revenue: revenueCount,
          expense: expenseCount,
          total: revenueCount + expenseCount
        }
      }
    });

  } catch (error) {
    console.error('[Financial Report Error]:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Erro interno ao processar o relatório financeiro.'
    });
  }
});

export default router;