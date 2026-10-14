const express = require('express');
const app = express();

app.use(express.json());

app.delete('/api/users/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    const result = await db.query(
      'DELETE FROM users WHERE id = $1 RETURNING id',
      [userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: 'Usuário não encontrado'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Usuário removido permanentemente',
      userId: result.rows[0].id
    });
  } catch (error) {
    console.error('Erro ao remover usuário:', error);

    return res.status(500).json({
      error: 'Erro interno ao remover usuário'
    });
  }
});

app.listen(3000);
