import express from 'express';
import { body, param, validationResult } from 'express-validator';
import { PrismaClient } from '@prisma/client';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * Middleware para simulação de autenticação e contexto do Tenant.
 * Em produção, utilize middlewares de autenticação JWT/OAuth2 robustos.
 */
const authenticateAndSetContext = (req, res, next) => {
  // Exemplo de payload extraído de um token JWT validado
  req.user = {
    id: 'usr_admin_123',
    tenantId: 'company_abc_456',
    role: 'ADMIN', // Roles: 'ADMIN', 'MEMBER', etc.
  };
  next();
};

/**
 * DELETE /api/v1/users/:id
 * Remove permanentemente um usuário da base mantendo isolamento por tenant.
 */
router.delete(
  '/users/:id',
  authenticateAndSetContext,
  [
    // Sanitização e validação do parâmetro para prevenir Injeção (OWASP A03)
    param('id')
      .trim()
      .notEmpty()
      .withMessage('O ID do usuário é obrigatório.')
      .isUUID()
      .withMessage('O ID fornecido possui formato inválido.'),
  ],
  async (req, res) => {
    // 1. Validação de Entrada
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Requisição inválida',
        details: errors.array().map((err) => ({ field: err.param, message: err.msg })),
      });
    }

    const targetUserId = req.params.id;
    const { tenantId: currentTenantId, role: currentUserRole, id: currentUserId } = req.user;

    try {
      // 2. Controle de Acesso Baseado em Função - RBAC (OWASP A01: Broken Access Control)
      if (currentUserRole !== 'ADMIN') {
        return res.status(403).json({
          error: 'Acesso negado. Apenas administradores podem remover usuários.',
        });
      }

      // 3. Prevenção de Autoexclusão Acidental / Comprometimento do Tenant
      if (targetUserId === currentUserId) {
        return res.status(400).json({
          error: 'Operação não permitida. Você não pode remover sua própria conta de administrador.',
        });
      }

      // 4. Busca do usuário garantindo Isolamento Multilocatário (Tenant Boundary Check)
      const userToDelete = await prisma.user.findFirst({
        where: {
          id: targetUserId,
          tenantId: currentTenantId, // Garante que o usuário pertence ao MESMO tenant do admin
        },
      });

      // Se o usuário não existir no tenant atual, retorna 404 para não vazar a existência do ID em outro tenant
      if (!userToDelete) {
        return res.status(404).json({
          error: 'Usuário não encontrado.',
        });
      }

      // 5. Exclusão Permanente do Banco de Dados
      await prisma.user.delete({
        where: {
          id: userToDelete.id,
        },
      });

      // 6. Resposta de Confirmação Sucesso
      return res.status(200).json({
        success: true,
        message: 'Usuário removido permanentemente com sucesso.',
        data: {
          id: userToDelete.id,
          removedAt: new Date().toISOString(),
        },
      });
    } catch (error) {
      // Log interno para monitoramento (OWASP A09: Security Logging and Monitoring Failures)
      console.error(`[ERROR][DELETE_USER] Tenant: ${currentTenantId} | TargetUser: ${targetUserId} | Error:`, error);

      // Tratamento genérico de erro para não expor stack trace (OWASP A05: Security Misconfiguration)
      return res.status(500).json({
        error: 'Erro interno ao processar a remoção do usuário.',
      });
    }
  }
);

export default router;