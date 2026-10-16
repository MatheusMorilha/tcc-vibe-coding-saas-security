const express = require('express');
const router = express.Router();
const db = require('../db'); // Instância do Pool do pg (node-postgres)
const { authenticateToken, authorizeAdmin } = require('../middlewares/auth');

/**
 * @routeDELETE /api/users/:id
 * @descRemove permanentemente um usuário da base (SaaS Multilocatário)
 * @accessPrivate (Admin do Tenant)
 */
router.delete('/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const userIdToDelete = req.params.id;

    // O tenantId DEVE vir do contexto do usuário autenticado (JWT/Sessão), NUNCA do payload da requisição
    const tenantId = req.user.tenantId;
    const currentUserId = req.user.id;

    // 1. Validação de formato do ID (Previne Injection / Rejeita dados malformados)
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userIdToDelete)) {
      return res.status(400).json({ error: 'Identificador de usuário inválido.' });
    }

    // 2. Prevenção de Auto-Deleção (Regra de Negócio / Proteção de Conta)
    if (userIdToDelete === currentUserId) {
      return res.status(422).json({ error: 'Você não pode remover sua própria conta através desta rota.' });
    }

    // 3. Execução da deleção garantindo Isolamento Multilocatário (Tenant Isolation)
    // A cláusula `tenant_id = $2` impede IDOR e acesso cruzado entre locatários
    const deleteQuery = `
      DELETE FROM users
      WHERE id = $1 AND tenant_id = $2
      RETURNING id, email;
    `;

    const result = await db.query(deleteQuery, [userIdToDelete, tenantId]);

    // 4. Verificação de existência dentro do Tenant do requisitante
    if (result.rowCount === 0) {
      // Retorna 404 para não revelar a existência do recurso em outro tenant
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    // 5. Confirmação da Operação
    return res.status(200).json({
      message: 'Usuário removido permanentemente com sucesso.',
      data: {
        id: result.rows[0].id,
        deletedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    // 6. Tratameto Seguro de Erros (A05:2021 – Security Misconfiguration / OWASP Logging)
    // O erro interno é logado no servidor, mas NÃO exposto na resposta para evitar Information Disclosure
    console.error(`[ERROR][Tenant: ${req.user?.tenantId}] Falha ao deletar usuário:`, error);

    return res.status(500).json({
      error: 'Erro interno ao processar a solicitação. Tente novamente mais tarde.'
    });
  }
});

module.exports = router;