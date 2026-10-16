const express = require('express');
const router = express.Router();
// Importe seu cliente de banco de dados (ex: Knex, Prisma, PG Client)
const db = require('../config/database');

/**
 * Middlewares de contexto/autenticação esperados:
 * - authenticateToken: Valida o JWT ou sessão do usuário requisitante e anexa `req.user`.
 * - authorizeRole: Valida se o usuário tem permissão para deletar (ex: ADMIN).
 */

/**
 * DELETE /api/v1/users/:id
 * Remove permanentemente um usuário garantindo o isolamento do tenant.
 */
router.delete('/users/:id', async (req, res) => {
  try {
    // 1. Captura e higienização/validação dos inputs
    const targetUserId = String(req.params.id).trim();

    // Garantir contexto de autenticação (A01: Broken Access Control)
    const requestingUser = req.user;
    if (!requestingUser || !requestingUser.tenantId) {
      return res.status(401).json({
        error: 'Não autorizado',
        code: 'UNAUTHORIZED'
      });
    }

    const tenantId = requestingUser.tenantId;

    // Validação de formato (prevenção básica de payload inválido)
    if (!targetUserId) {
      return res.status(400).json({
        error: 'Identificador do usuário inválido',
        code: 'BAD_REQUEST'
      });
    }

    // Regra de Negócio/Segurança: Impedir a autoexclusão pela mesma rota administrativa
    if (targetUserId === requestingUser.id) {
      return res.status(400).json({
        error: 'Não é permitido remover a si mesmo por esta rota',
        code: 'SELF_DELETION_NOT_ALLOWED'
      });
    }

    // 2. Execução segura da deleção no banco de dados
    // Prevenção contra SQL Injection (A03: Injection) usando queries parametrizadas
    // Prevenção contra BOLA/IDOR (A01: Broken Access Control) OBRIGANDO o filtro pelo tenantId
    const query = `
      DELETE FROM users
      WHERE id = $1 AND tenant_id = $2
      RETURNING id, email;
    `;

    const result = await db.query(query, [targetUserId, tenantId]);

    // 3. Verificação de existência dentro do escopo do locatário
    if (result.rowCount === 0) {
      // Retornamos 404 genérico para evitar enumeração de IDs de outros tenants
      return res.status(404).json({
        error: 'Usuário não encontrado',
        code: 'USER_NOT_FOUND'
      });
    }

    // 4. Auditoria de Segurança (A09: Security Logging and Monitoring Failures)
    console.info(`[AUDIT] Usuário ${targetUserId} deletado permanentemente do tenant ${tenantId} pelo operador ${requestingUser.id}`);

    // 5. Retorno de confirmação da operação
    return res.status(200).json({
      success: true,
      message: 'Usuário removido permanentemente com sucesso.',
      data: {
        deletedUserId: targetUserId
      }
    });

  } catch (error) {
    // A05: Security Misconfiguration - Não expor stack traces ou detalhes internos do banco
    console.error('[ERROR] Falha ao deletar usuário:', error);

    return res.status(500).json({
      error: 'Ocorreu um erro interno ao processar a solicitação.',
      code: 'INTERNAL_SERVER_ERROR'
    });
  }
});

module.exports = router;