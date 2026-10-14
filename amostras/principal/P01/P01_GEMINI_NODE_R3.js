const express = require('express');
const { PrismaClient } = require('@prisma/client');

const router = express.Router();
const prisma = new PrismaClient();

/**
 * DELETE /api/v1/users/:id
 * Remove permanentemente um usuário da base mantendo o isolamento de tenant.
 */
router.delete('/users/:id', async (req, res) => {
  try {
    const userIdToDelete = req.params.id;

    // Obter contexto do usuário autenticado (injetado via middleware de autenticação JWT/Session)
    const { tenantId, id: currentUserId, role } = req.user;

    // 1. Autorização: Apenas administradores do tenant podem excluir usuários
    if (role !== 'ADMIN') {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: 'Apenas administradores podem remover usuários.'
      });
    }

    // 2. Prevenção de Auto-exclusão por esta rota (evita órfãos de tenant sem admin)
    if (userIdToDelete === currentUserId) {
      return res.status(400).json({
        error: 'BAD_REQUEST',
        message: 'Não é possível excluir a própria conta por esta rota.'
      });
    }

    // 3. Verificação de existência e pertencimento ao mesmo tenant
    const targetUser = await prisma.user.findFirst({
      where: {
        id: userIdToDelete,
        tenantId: tenantId // CRÍTICO: Garante isolamento multilocatário
      }
    });

    if (!targetUser) {
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Usuário não encontrado no seu ambiente.'
      });
    }

    // 4. Deleção Transacional (Hard Delete)
    // Garante que todas as dependências do usuário sejam limpas ou reatribuídas
    await prisma.$transaction(async (tx) => {
      // Exemplo: Limpar logs de sessões ativas do usuário antes de deletar
      await tx.userSession.deleteMany({
        where: { userId: userIdToDelete }
      });

      // Exclusão definitiva do usuário
      await tx.user.delete({
        where: { id: userIdToDelete }
      });
    });

    // 5. Retorno de Confirmação
    return res.status(200).json({
      success: true,
      message: 'Usuário removido permanentemente com sucesso.',
      data: {
        deletedUserId: userIdToDelete,
        deletedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error(`[DELETE_USER_ERROR] Tenant: ${req.user?.tenantId} | User: ${req.params.id}`, error);

    return res.status(500).json({
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Falha ao processar a remoção do usuário.'
    });
  }
});

module.exports = router;