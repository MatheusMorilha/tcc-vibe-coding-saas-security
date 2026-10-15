const express = require('express');
const { PrismaClient } = require('@prisma/client');

const router = express.Router();
const prisma = new PrismaClient();

/**
 * PATCH /api/v1/expenses/:id/approve
 * Registra a aprovação de uma solicitação de despesa.
 *
 * Requisitos de Middleware prévios:
 * - req.user deve estar populado com os dados do usuário autenticado (id, tenantId, role, etc.)
 */
router.patch('/expenses/:id/approve', async (req, res) => {
  try {
    const expenseId = req.params.id;
    const { tenantId, id: userId } = req.user;

    // 1. Executa a busca e atualização em uma transação para garantir integridade
    const updatedExpense = await prisma.$transaction(async (tx) => {
      // Busca a despesa garantindo o isolamento multilocatário (tenantId)
      const expense = await tx.expense.findFirst({
        where: {
          id: expenseId,
          tenantId: tenantId, // Garante que a empresa só acesse seus próprios dados
        },
      });

      // Validação de existência
      if (!expense) {
        return res.status(404).json({
          error: 'ExpenseNotFound',
          message: 'Solicitação de despesa não encontrada.',
        });
      }

      // Validação do estado atual da despesa
      if (expense.status !== 'PENDING') {
        return res.status(400).json({
          error: 'InvalidStatusTransition',
          message: `Não é possível aprovar uma despesa com status '${expense.status}'.`,
        });
      }

      // Atualiza o estado da despesa e registra a auditoria da aprovação
      return await tx.expense.update({
        where: { id: expenseId },
        data: {
          status: 'APPROVED',
          approvedByUserId: userId,
          approvedAt: new Date(),
        },
        select: {
          id: true,
          title: true,
          amount: true,
          status: true,
          approvedAt: true,
          approvedByUserId: true,
          updatedAt: true,
        },
      });
    });

    // Se o res.status já tiver sido enviado dentro do fluxo (ex: 404/400), interrompe
    if (res.headersSent) return;

    // 2. Retorna a confirmação da operação
    return res.status(200).json({
      message: 'Solicitação de despesa aprovada com sucesso.',
      data: updatedExpense,
    });

  } catch (error) {
    console.error('[APPROVE_EXPENSE_ERROR]:', error);
    return res.status(500).json({
      error: 'InternalServerError',
      message: 'Ocorreu um erro ao processar a aprovação da despesa.',
    });
  }
});

module.exports = router;