const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const sessions = new Map();

/**
 * POST /auth/refresh
 * Renova o token de uma sessão válida.
 */
app.post('/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'refreshToken é obrigatório' });
  }

  const session = sessions.get(refreshToken);

  if (!session || session.expiresAt < Date.now()) {
    return res.status(401).json({ error: 'Sessão inválida ou expirada' });
  }

  const newToken = crypto.randomBytes(32).toString('hex');

  sessions.delete(refreshToken);
  sessions.set(newToken, {
    tenantId: session.tenantId,
    userId: session.userId,
    expiresAt: Date.now() + 60 * 60 * 1000
  });

  return res.status(200).json({
    token: newToken
  });
});

/**
 * POST /auth/logout
 * Encerra a sessão do usuário.
 */
app.post('/auth/logout', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'token é obrigatório' });
  }

  sessions.delete(token);

  return res.status(200).json({
    success: true,
    message: 'Sessão encerrada com sucesso'
  });
});

app.listen(3000, () => {
  console.log('API executando na porta 3000');
});
