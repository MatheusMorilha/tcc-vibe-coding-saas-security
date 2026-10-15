const express = require('express');
const { PrismaClient } = require('@prisma/client');

const router = express.Router();
const prisma = new PrismaClient();

/**
 * PATCH /api/v1/expenses/:id/approve
 * Registra a aprovação de uma solicitação de despesa no contexto multi-tenant.
 */
router.patch('/expenses/:id/approve', async (req, res) => {
  try {
    const expenseId = req.params.id;

    // Dados injetados pelo middleware de autenticação/autorização da sessão do JWT
    const { tenantId, userId, role } = req.user;

    // 1. Controle de Acesso e Permissão de Usuário (RBAC)
    if (!['ADMIN', 'FINANCIAL_APPROVER'].includes(role)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Você não tem permissão para aprovar despesas.'
      });
    }

    // 2. Transação para garantir consistência e evitar race conditions
    const result = await prisma.$transaction(async (tx) => {
      // Busca a despesa garantindo estritamente o isolamento do tenant (tenant_id)
      const expense = await tx.expense.findFirst({
        where: {
          id: expenseId,
          tenantId: tenantId // Garantia de isolamento multi-tenant
        }
      });

      if (!expense) {
        return { error: 'NOT_FOUND' };
      }

      // Validação do estado atual do fluxo de aprovação
      if (expense.status === 'APPROVED') {
        return { error: 'ALREADY_APPROVED' };
      }

      if (expense.status !== 'PENDING') {
        return { error: 'INVALID_STATUS', currentStatus: expense.status };
      }

      // Atualiza o estado da despesa gravando o histórico de aprovação
      const updatedExpense = await tx.expense.update({
        where: { id: expenseId },
        data: {
          status: 'APPROVED',
          approvedAt: new Date(),
          approvedById: userId
        },
        select: {
          id: true,
          description: true,
          amount: true,
          status: true,
          approvedAt: true,
          approvedById: true,
          updatedAt: true
        }
      });

      return { success: true, data: updatedExpense };
    });

    // 3. Tratamento dos retornos da transação
    if (result.error === 'NOT_FOUND') {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Solicitação de despesa não encontrada.'
      });
    }

    if (result.error === 'ALREADY_APPROVED') {
      return res.status(409).json({
        error: 'Conflict',
        message: 'Esta solicitação de despesa já foi aprovada anteriormente.'
      });
    }

    if (result.error === 'INVALID_STATUS') {
      return res.status(422).json({
        error: 'Unprocessable Entity',
        message: `Não é possível aprovar uma despesa com status '${result.currentStatus}'.`
      });
    }

    // Retorno de sucesso (200 OK)
    return res.status(200).json({
      message: 'Solicitação de despesa aprovada com sucesso.',
      data: result.data
    });

  } catch (error) {
    console.error('[APPROVE_EXPENSE_ERROR]:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Ocorreu um erro ao processar a aprovação da despesa.'
    });
  }
});

module.exports = router;