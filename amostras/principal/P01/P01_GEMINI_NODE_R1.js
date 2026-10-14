const express = require('express');
const { PrismaClient } = require('@prisma/client');

const router = express.Router();
const prisma = new PrismaClient();

/**
 * DELETE /api/v1/users/:userId
 * Remove permanentemente um usuário da base de dados respeitando o isolamento do tenant.
 */
router.delete('/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    // 1. Contexto do usuário autenticado injetado via middleware de autenticação/autorização
    const tenantIdContext = req.tenantId; // ex: req.user.companyId
    const requestingUserId = req.user?.id;

    if (!tenantIdContext) {
      return res.status(403).json({
        error: 'Acesso negado: Contexto da empresa não identificado.'
      });
    }

    // 2. Impede que o usuário remova a si mesmo diretamente por esta rota (se aplicável)
    if (userId === requestingUserId) {
      return res.status(400).json({
        error: 'Operação inválida: Não é possível remover a própria conta através desta rota.'
      });
    }

    // 3. Busca e validação de existência do usuário no MESMO tenant
    const userToDelete = await prisma.user.findFirst({
      where: {
        id: userId,
        companyId: tenantIdContext // Garantia fundamental de segurança multi-tenant
      }
    });

    if (!userToDelete) {
      return res.status(404).json({
        error: 'Usuário não encontrado ou não pertence a esta empresa.'
      });
    }

    // 4. Execução da remoção física (Hard Delete)
    await prisma.user.delete({
      where: {
        id: userId
      }
    });

    // 5. Retorno de confirmação da operação
    return res.status(200).json({
      success: true,
      message: 'Usuário removido permanentemente com sucesso.',
      data: {
        removedUserId: userId,
        deletedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error(`[DeleteUserError] Tenant: ${req.tenantId} | Error:`, error);

    // Tratamento para violação de chave estrangeira (FK Constraint), caso o banco exija
    if (error.code === 'P2003') {
      return res.status(409).json({
        error: 'Não é possível remover o usuário pois existem registros associados pendentes.'
      });
    }

    return res.status(500).json({
      error: 'Erro interno ao tentar remover o usuário.'
    });
  }
});

module.exports = router;