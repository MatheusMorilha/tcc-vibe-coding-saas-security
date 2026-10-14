// routes/users.js
const express = require('express');
const router = express.Router();
const { pool } = require('../db'); // pool do 'pg'
const { authenticate } = require('../middleware/authenticate'); // extrai req.user = { id, companyId, role }
const { requireRole } = require('../middleware/authorize');

/**
 * DELETE /api/companies/:companyId/users/:userId
 * Remove permanentemente um usuário da base, restrito ao tenant do requisitante.
 */
router.delete(
  '/companies/:companyId/users/:userId',
  authenticate,
  requireRole(['admin', 'owner']),
  async (req, res) => {
    const { companyId, userId } = req.params;
    const requester = req.user;

    // 1. Validação básica de entrada
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(companyId) || !uuidRegex.test(userId)) {
      return res.status(400).json({ error: 'Identificadores inválidos.' });
    }

    // 2. Garantia de isolamento de tenant: o requisitante só pode operar
    // dentro da própria empresa, mesmo que o companyId da URL seja manipulado.
    if (requester.companyId !== companyId) {
      return res.status(403).json({ error: 'Operação não permitida para este tenant.' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 3. Confirma que o usuário existe E pertence ao mesmo tenant do requisitante
      const userResult = await client.query(
        `SELECT id, email, company_id
         FROM users
         WHERE id = $1 AND company_id = $2
         FOR UPDATE`,
        [userId, companyId]
      );

      if (userResult.rowCount === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Usuário não encontrado nesta empresa.' });
      }

      const targetUser = userResult.rows[0];

      // 4. Regra de negócio: impedir que o último admin/owner da empresa seja removido
      if (['admin', 'owner'].includes(requester.role)) {
        const adminCountResult = await client.query(
          `SELECT COUNT(*)::int AS total
           FROM users
           WHERE company_id = $1 AND role IN ('admin', 'owner') AND id != $2`,
          [companyId, userId]
        );
        const remainingAdmins = adminCountResult.rows[0].total;
        const isTargetAdmin = await client.query(
          `SELECT role FROM users WHERE id = $1`,
          [userId]
        );
        if (
          ['admin', 'owner'].includes(isTargetAdmin.rows[0].role) &&
          remainingAdmins === 0
        ) {
          await client.query('ROLLBACK');
          return res.status(409).json({
            error: 'Não é possível remover o único administrador da empresa.',
          });
        }
      }

      // 5. Remove dependências relacionadas ao usuário (ajuste conforme seu schema)
      await client.query(`DELETE FROM user_sessions WHERE user_id = $1`, [userId]);
      await client.query(`DELETE FROM user_permissions WHERE user_id = $1`, [userId]);
      await client.query(`DELETE FROM audit_tokens WHERE user_id = $1`, [userId]);

      // 6. Remove o usuário, sempre com o filtro duplo (id + company_id)
      const deleteResult = await client.query(
        `DELETE FROM users WHERE id = $1 AND company_id = $2 RETURNING id`,
        [userId, companyId]
      );

      if (deleteResult.rowCount === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Usuário não encontrado nesta empresa.' });
      }

      await client.query('COMMIT');

      // 7. Log de auditoria (fora da transação de dados, mas relevante para rastreabilidade)
      console.info(
        `[AUDIT] Usuário ${userId} (${targetUser.email}) removido do tenant ${companyId} por ${requester.id} em ${new Date().toISOString()}`
      );

      return res.status(200).json({
        success: true,
        message: 'Usuário removido permanentemente.',
        data: {
          userId,
          companyId,
          removedAt: new Date().toISOString(),
        },
      });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Erro ao remover usuário:', err);
      return res.status(500).json({ error: 'Erro interno ao processar a exclusão.' });
    } finally {
      client.release();
    }
  }
);

module.exports = router;