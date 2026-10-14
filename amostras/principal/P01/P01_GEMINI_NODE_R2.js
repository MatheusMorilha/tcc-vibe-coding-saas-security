import express from 'express';
import { PrismaClient } from '@prisma/client';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * DELETE /api/v1/users/:userId
 * Exclui permanentemente um usuário da organização/tenant atual.
 *
 * Pressupõe que middlewares de autenticação prévios injetaram em `req.user`:
 * - req.user.id: ID do usuário que faz a requisição
 * - req.user.tenantId: ID da empresa/tenant do usuário logado
 * - req.user.role: Papel/Função do usuário (ex: 'ADMIN')
 */
router.delete('/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { tenantId: currentTenantId, id: currentUserId, role: currentUserRole } = req.user;

    // 1. Controle de Acesso (RBAC)
    if (currentUserRole !== 'ADMIN') {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Apenas administradores podem remover usuários.'
      });
    }

    // 2. Prevenção de autodeleção nesta rota
    if (userId === currentUserId) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Você não pode excluir sua própria conta por este fluxo.'
      });
    }

    // 3. Garantia de Tenant Isolation: Busca o usuário exigindo o tenantId
    const targetUser = await prisma.user.findFirst({
      where: {
        id: userId,
        tenantId: currentTenantId // Garante que o usuário pertence à empresa logada
      }
    });

    if (!targetUser) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Usuário não encontrado na sua organização.'
      });
    }

    // 4. Execução em Transação para garantir integridade e limpeza
    await prisma.$transaction(async (tx) => {
      // Opcional: Se houver tabelas vinculadas sem CASCADE no banco (ex: sessões, tokens),
      // limpe-as aqui antes da exclusão do usuário.
      await tx.userSession.deleteMany({
        where: { userId: targetUser.id }
      });

      // Remoção permanente do usuário
      await tx.user.delete({
        where: {
          id: targetUser.id
        }
      });
    });

    // 5. Retorno de confirmação
    return res.status(200).json({
      success: true,
      message: 'Usuário removido permanentemente com sucesso.',
      data: {
        deletedUserId: targetUser.id,
        deletedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error(`[DELETE /users/${req.params.userId}] Erro ao remover usuário:`, error);

    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Ocorreu um erro ao tentar remover o usuário.'
    });
  }
});

export default router;