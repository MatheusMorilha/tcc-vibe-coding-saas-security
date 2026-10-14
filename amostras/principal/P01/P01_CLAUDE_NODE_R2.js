// routes/users.js
const express = require('express');
const router = express.Router();
const prisma = require('../lib/prisma');
const authenticate = require('../middlewares/authenticate');
const authorize = require('../middlewares/authorize');

/**
 * DELETE /api/companies/:companyId/users/:userId
 * Remove permanentemente um usuário da base.
 * Requer autenticação + permissão de admin dentro do MESMO tenant.
 */
router.delete(
  '/companies/:companyId/users/:userId',
  authenticate,                 // valida token e popula req.user
  authorize(['admin', 'owner']),// garante que req.user tem papel permitido
  async (req, res) => {
    const { companyId, userId } = req.params;

    // 1. Validação básica dos identificadores (evita queries com lixo)
    if (!isValidId(companyId) || !isValidId(userId)) {
      return res.status(400).json({
        error: 'Identificadores inválidos.',
      });
    }

    // 2. Isolamento de tenant: o requisitante só pode operar
    //    dentro da própria empresa (nunca confiar em companyId do body/token sem checar)
    if (req.user.companyId !== companyId) {
      return res.status(403).json({
        error: 'Operação não permitida para este tenant.',
      });
    }

    try {
      // 3. Confirma que o usuário-alvo existe e pertence à mesma empresa
      const targetUser = await prisma.user.findFirst({
        where: { id: userId, companyId: companyId },
      });

      if (!targetUser) {
        return res.status(404).json({
          error: 'Usuário não encontrado nesta empresa.',
        });
      }

      // 4. Impede que o usuário exclua a si mesmo por engano,
      //    ou (opcional) impede exclusão do único owner restante
      if (targetUser.id === req.user.id) {
        return res.status(400).json({
          error: 'Você não pode excluir sua própria conta por esta rota.',
        });
      }

      // 5. Exclusão permanente, dentro de uma transação
      //    (remove também vínculos dependentes, se existirem)
      await prisma.$transaction(async (tx) => {
        await tx.userSession.deleteMany({ where: { userId } });
        await tx.userPermission.deleteMany({ where: { userId } });
        await tx.user.delete({ where: { id: userId } });
      });

      // 6. Log de auditoria — essencial para operações destrutivas
      await prisma.auditLog.create({
        data: {
          action: 'USER_DELETED',
          companyId,
          performedBy: req.user.id,
          targetId: userId,
          metadata: { targetEmail: targetUser.email },
        },
      });

      return res.status(200).json({
        success: true,
        message: `Usuário ${userId} removido permanentemente.`,
      });
    } catch (error) {
      console.error('Erro ao excluir usuário:', error);
      return res.status(500).json({
        error: 'Erro interno ao processar a exclusão.',
      });
    }
  }
);

function isValidId(id) {
  // ajuste conforme o formato real (UUID, cuid, ObjectId, etc.)
  return typeof id === 'string' && /^[a-zA-Z0-9_-]{8,36}$/.test(id);
}

module.exports = router;