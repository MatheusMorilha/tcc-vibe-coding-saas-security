import express from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const router = express.Router();

/**
 * PUT /api/v1/users/:userId/permissions
 * Altera as permissões de um usuário no contexto da empresa ativa (tenantId).
 */
router.put('/users/:userId/permissions', async (req, res) => {
  try {
    // 1. Contexto extraído do Middleware de Autenticação/Multitenancy
    const tenantId = req.user?.tenantId;
    const actorId = req.user?.id;
    const actorRole = req.user?.role;

    // 2. Validação básica de acesso/permissão do solicitante
    if (!tenantId || !actorId) {
      return res.status(401).json({ error: 'Contexto de autenticação inválido.' });
    }

    if (actorRole !== 'ADMIN') {
      return res.status(403).json({ error: 'Apenas administradores podem alterar permissões.' });
    }

    const { userId: targetUserId } = req.params;
    const { permissions: newPermissions } = req.body;

    // Validação de entrada
    if (!Array.isArray(newPermissions)) {
      return res.status(400).json({ error: 'O campo "permissions" deve ser um array de strings.' });
    }

    // 3. Buscar o usuário-alvo GARANTINDO o filtro por tenantId (Isolamento Multitenant)
    const targetUser = await prisma.user.findFirst({
      where: {
        id: targetUserId,
        tenantId: tenantId, // Garante que o usuário pertence à mesma empresa
      },
    });

    if (!targetUser) {
      return res.status(404).json({ error: 'Usuário não encontrado nesta empresa.' });
    }

    const oldPermissions = targetUser.permissions;

    // 4. Executar Atualização e Registro de Auditoria em Transação Atômica
    const result = await prisma.$transaction(async (tx) => {
      // Atualizar as permissões do usuário
      const updatedUser = await tx.user.update({
        where: { id: targetUserId },
        data: { permissions: newPermissions },
        select: { id: true, email: true, role: true, permissions: true },
      });

      // Registrar o log de auditoria
      const auditLog = await tx.auditLog.create({
        data: {
          tenantId: tenantId,
          actorId: actorId,
          targetUserId: targetUserId,
          action: 'USER_PERMISSIONS_UPDATED',
          details: {
            oldPermissions: oldPermissions,
            newPermissions: newPermissions,
          },
          ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
          userAgent: req.get('user-agent') || null,
        },
      });

      return { updatedUser, auditLogId: auditLog.id };
    });

    return res.status(200).json({
      message: 'Permissões atualizadas e auditoria registrada com sucesso.',
      data: result.updatedUser,
      auditLogId: result.auditLogId,
    });

  } catch (error) {
    console.error('Erro ao atualizar permissões:', error);
    return res.status(500).json({ error: 'Erro interno ao processar a solicitação.' });
  }
});

export default router;