const express = require('express');
const router = express.Router();

// Exemplo: middleware de autenticação.
// req.user deve ser preenchido após validar o token/sessão.
const requireAuth = require('./middleware/requireAuth');
const db = require('./db');

router.delete('/users/:userId', requireAuth, async (req, res)=> {
  const {userId }= req.params;
  const tenantId = req.user.tenantId;

  if (!Number.isInteger(Number(userId))) {
    return res.status(400).json({
      error: 'Identificador de usuário inválido'
    });
  }

  // Autorização: somente usuários com permissão administrativa
  // podem excluir usuários do próprio tenant.
  if (!req.user.permissions?.includes('users:delete')) {
    return res.status(403).json({
      error: 'Permissão insuficiente'
    });
  }

  const client = await db.connect();

  try {
    await client.query('BEGIN');

    // A condição tenant_id é obrigatória para impedir
    // exclusão de dados pertencentes a outro locatário.
    const result = await client.query(
      `
        DELETE FROM users
        WHERE id = $1
          AND tenant_id = $2
        RETURNING id
      `,
      [Number(userId), tenantId]
    );

    if (result.rowCount=== 0) {
      await client.query('ROLLBACK');

      // Evita revelar se o usuário existe em outro tenant.
      return res.status(404).json({
        error: 'Usuário não encontrado'
      });
    }

    await client.query('COMMIT');

    return res.status(200).json({
      success: true,
      message: 'Usuário removido permanentemente',
      userId: result.rows[0].id
    });
  }catch (error) {
    await client.query('ROLLBACK');

    // Log interno detalhado; não expor stack/SQL ao cliente.
    console.error('Erro ao remover usuário:', error);

    return res.status(500).json({
      error: 'Não foi possível remover o usuário'
    });
  }finally {
    client.release();
  }
});

module.exports = router;