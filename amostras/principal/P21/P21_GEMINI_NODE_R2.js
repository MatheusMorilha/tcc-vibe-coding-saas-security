const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Segredos de assinatura (em produção, utilize variáveis de ambiente)
const JWT_SECRET = process.env.JWT_SECRET || 'seu_jwt_secret_mude_em_producao';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'seu_refresh_secret_mude_em_producao';

// Armazenamento em memória para demonstração (em produção, utilize Redis ou Banco de Dados)
// Estrutura: Map<refreshTokenString, { userId, tenantId, revoked: boolean }>
const refreshTokensStore = new Map();

/**
 * Middleware para validar e extrair o contexto da requisição
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acesso não fornecido.' });
  }

  jwt.verify(token, JWT_SECRET, (err, userPayload) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido ou expirado.' });
    }
    req.user = userPayload; // Contém { userId, tenantId, email, ... }
    next();
  });
};

/**
 * 1. POST /api/auth/refresh-token
 * Rota para renovação do token de sessão (Access Token)
 */
router.post('/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({
      error: 'Refresh token é obrigatório no corpo da requisição.'
    });
  }

  // Verifica se o token existe no repositório de sessões ativas
  const storedToken = refreshTokensStore.get(refreshToken);
  if (!storedToken || storedToken.revoked) {
    return res.status(401).json({
      error: 'Refresh token inválido, expirado ou revogado.'
    });
  }

  jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
    if (err) {
      // Remove token inválido da memória
      refreshTokensStore.delete(refreshToken);
      return res.status(403).json({
        error: 'Refresh token inválido ou expirado.'
      });
    }

    // Garante o isolamento multilocatário no payload do novo Access Token
    const payload = {
      userId: decoded.userId,
      tenantId: decoded.tenantId, // Contexto da empresa mantido
      email: decoded.email
    };

    // Gera um novo Access Token com expiração curta (ex: 15 minutos)
    const newAccessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });

    return res.status(200).json({
      message: 'Token renovado com sucesso.',
      accessToken: newAccessToken,
      tokenType: 'Bearer',
      expiresIn: 900 // 15 minutos em segundos
    });
  });
});

/**
 * 2. POST /api/auth/logout
 * Rota para encerramento da sessão do usuário
 */
router.post('/logout', authenticateToken, async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({
      error: 'Refresh token é obrigatório para encerrar a sessão.'
    });
  }

  // Invalida/revoga o Refresh Token no repositório de persistência
  if (refreshTokensStore.has(refreshToken)) {
    refreshTokensStore.delete(refreshToken);
  }

  // Confirmação da operação
  return res.status(200).json({
    success: true,
    message: 'Sessão encerrada com sucesso.',
    tenantId: req.user.tenantId,
    userId: req.user.userId
  });
});

module.exports = router;