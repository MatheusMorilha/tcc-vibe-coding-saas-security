const express = require('express');
const { PrismaClient } = require('@prisma/client');

const router = express.Router();
const prisma = new PrismaClient();

/**
 * PUT /api/v1/users/:userId/permissions
 * Altera as permissões de um usuário da empresa e registra a ação na trilha de auditoria.
 */
router.put('/users/:userId/permissions', async (req, res) => {
  try {
    // 1. Identificação do Tenant e Usuário Operador (injetados por middleware de autenticação/JWT)
    const tenantId = req.user?.tenantId;
    const operatorId = req.user?.id;

    if (!tenantId || !operatorId) {
      return res.status(401).json({ error: 'Sessão inválida ou tenant não identificado.' });
    }

    const { userId } = req.params;
    const { permissions } = req.body; // Expectativa: Array de strings, ex: ["READ_REPORTS", "WRITE_PRODUCTS"]

    if (!Array.isArray(permissions)) {
      return res.status(400).json({ error: 'O campo "permissions" deve ser um array.' });
    }

    // 2. Busca o usuário garantindo o isolamento de tenant
    const targetUser = await prisma.user.findFirst({
      where: {
        id: userId,
        tenantId: tenantId // Trava de segurança multilocatário
      }
    });

    if (!targetUser) {
      return res.status(404).json({ error: 'Usuário não encontrado nesta organização.' });
    }

    const previousPermissions = targetUser.permissions;

    // 3. Execução em Transação Relacional (Garante atomicidade da atualização + auditoria)
    const result = await prisma.$transaction(async (tx) => {
      // 3.1 Atualiza permissões do usuário target
      const updatedUser = await tx.user.update({
        where: { id: userId },
        data: { permissions }
      });

      // 3.2 Registra o evento na Trilha de Auditoria
      const auditLog = await tx.auditLog.create({
        data: {
          tenantId,
          action: 'USER_PERMISSIONS_UPDATE',
          entity: 'User',
          entityId: userId,
          performedById: operatorId,
          details: {
            previousPermissions,
            newPermissions: permissions
          },
          ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
          userAgent: req.headers['user-agent'] || null
        }
      });

      return { updatedUser, auditLog };
    });

    // 4. Retorno de sucesso
    return res.status(200).json({
      message: 'Permissões atualizadas e auditadas com sucesso.',
      data: {
        userId: result.updatedUser.id,
        permissions: result.updatedUser.permissions,
        auditLogId: result.auditLog.id
      }
    });

  } catch (error) {
    console.error('[PERMISSIONS_UPDATE_ERROR]', error);
    return res.status(500).json({ error: 'Erro interno ao atualizar permissões.' });
  }
});

module.exports = router;