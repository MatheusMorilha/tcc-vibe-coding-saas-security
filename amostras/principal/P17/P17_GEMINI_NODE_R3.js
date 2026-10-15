import express from 'express';
import { PrismaClient } from '@prisma/client';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * PUT /api/v1/expenses/:id/approve
 * Registra a aprovação de uma solicitação de despesa.
 *
 * Requisitos de Contexto (geralmente injetados via Middleware de Autenticação/Tenancy):
 * - req.user.id: ID do usuário autenticado
 * - req.user.role: Papel/função do usuário (ex: ADMIN, MANAGER)
 * - req.user.organizationId: ID do tenant (empresa cliente)
 */
router.put('/expenses/:id/approve', async (req, res) => {
  try {
    const { id: expenseId } = req.params;
    const { id: userId, role: userRole, organizationId } = req.user;

    // 1. Validação de isolamento do Tenant e contexto de autenticação
    if (!organizationId) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Contexto de empresa (tenant) não identificado.'
      });
    }

    // 2. Controle de Acesso Baseado em Funções (RBAC)
    const ALLOWED_ROLES = ['ADMIN', 'MANAGER'];
    if (!ALLOWED_ROLES.includes(userRole)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Você não tem permissão para aprovar solicitações de despesa.'
      });
    }

    // 3. Execução em Transação para consistência e prevenção de Race Conditions
    const updatedExpense = await prisma.$transaction(async (tx) => {
      // 3.1. Busca a despesa aplicando estritamente o filtro de Tenant (multilocatário)
      const expense = await tx.expense.findFirst({
        where: {
          id: expenseId,
          organizationId: organizationId // Garante isolamento entre empresas
        }
      });

      // Se a despesa não existe ou pertence a outra empresa
      if (!expense) {
        throw { code: 'NOT_FOUND', message: 'Solicitação de despesa não encontrada.' };
      }

      // 3.2. Validação da máquina de estados
      if (expense.status === 'APPROVED') {
        throw { code: 'CONFLICT', message: 'Esta despesa já se encontra aprovada.' };
      }

      if (expense.status === 'REJECTED') {
        throw { code: 'UNPROCESSABLE_ENTITY', message: 'Não é possível aprovar uma despesa que já foi rejeitada.' };
      }

      // 3.3. Atualização do estado da despesa
      return await tx.expense.update({
        where: { id: expenseId },
        data: {
          status: 'APPROVED',
          approvedById: userId,
          approvedAt: new Date()
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
    });

    // 4. Retorno de confirmação da operação
    return res.status(200).json({
      success: true,
      message: 'Solicitação de despesa aprovada com sucesso.',
      data: updatedExpense
    });

  } catch (error) {
    // Trata exceções genéricas ou lançadas pela transação
    if (error.code === 'NOT_FOUND') {
      return res.status(404).json({ error: 'Not Found', message: error.message });
    }

    if (error.code === 'CONFLICT') {
      return res.status(409).json({ error: 'Conflict', message: error.message });
    }

    if (error.code === 'UNPROCESSABLE_ENTITY') {
      return res.status(422).json({ error: 'Unprocessable Entity', message: error.message });
    }

    console.error('[ApproveExpenseError]:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Ocorreu um erro ao processar a aprovação da despesa.'
    });
  }
});

export default router;