import express from 'express';
import { PrismaClient } from '@prisma/client';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * PATCH /api/v1/users/:id/permissions
 * Atualiza o cargo/permissão de um usuário e gera log de auditoria.
 */
router.patch('/users/:targetUserId/permissions', async (req, res) => {
  try {
    // 1. Extrai tenant e usuário logado do contexto de autenticação (Middleware de Auth)
    const { companyId, id: adminUserId } = req.user;
    const { targetUserId } = req.params;
    const { newRole } = req.body;

    // Validação básica do payload
    if (!newRole) {
      return res.status(400).json({ error: 'O campo newRole é obrigatório.' });
    }

    // 2. Busca o usuário-alvo GARANTINDO o isolamento por tenant (companyId)
    const targetUser = await prisma.user.findFirst({
      where: {
        id: targetUserId,
        companyId: companyId, // Impede Acesso Indevido Cross-Tenant
      },
    });

    if (!targetUser) {
      return res.status(404).json({ error: 'Usuário não encontrado na sua empresa.' });
    }

    // Evita atualizações redundantes
    if (targetUser.role === newRole) {
      return res.status(400).json({ error: 'O usuário já possui essa permissão.' });
    }

    const previousRole = targetUser.role;

    // 3. Transação Atômica: Atualiza o Usuário + Cria Log de Auditoria
    const [updatedUser, auditEntry] = await prisma.$transaction([
      // Atualiza as permissões/role do usuário
      prisma.user.update({
        where: { id: targetUserId },
        data: { role: newRole },
        select: { id: true, name: true, email: true, role: true },
      }),

      // Registra a alteração na Trilha de Auditoria
      prisma.auditLog.create({
        data: {
          companyId,
          performedBy: adminUserId,
          targetUser: targetUserId,
          action: 'UPDATE_USER_PERMISSIONS',
          details: {
            previousRole,
            newRole,
            updatedAt: new Date().toISOString(),
          },
          ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
        },
      }),
    ]);

    // 4. Retorna resposta de sucesso
    return res.status(200).json({
      message: 'Permissões atualizadas com sucesso.',
      user: updatedUser,
      auditId: auditEntry.id,
    });

  } catch (error) {
    console.error('Erro ao atualizar permissões:', error);
    return res.status(500).json({ error: 'Erro interno ao processar a alteração.' });
  }
});

export default router;