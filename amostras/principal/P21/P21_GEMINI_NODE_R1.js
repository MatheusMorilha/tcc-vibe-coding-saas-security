const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Configurações e Chaves
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'access_secret_key_saas';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'refresh_secret_key_saas';

// Simulação de banco de dados para Refresh Tokens ativos
// Em produção, utilize Redis ou uma tabela no banco relacional (PostgreSQL/MongoDB)
let refreshTokensDatabase = new Set();

/**
 * Função utilitária para gerar os tokens de acesso e de refresh.
 * Inclui tenant_id para garantir a isolamento multilocatário nas requisições.
 */
function generateTokens(payload){
  const accessToken = jwt.sign(
    { userId: payload.userId, tenantId: payload.tenantId, role: payload.role },
    ACCESS_TOKEN_SECRET,
    { expiresIn: '15m' } // Token de acesso curto
  );

  const refreshToken = jwt.sign(
    { userId: payload.userId, tenantId: payload.tenantId },
    REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' } // Token de refresh mais longo
  );

  return { accessToken, refreshToken };
}

// ==========================================
// ROTA 1: Renovação de Token de Sessão
// POST /api/auth/refresh
// ==========================================
router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({
      error: 'Token de renovação é obrigatório.'
    });
  }

  // Verifica se o token de refresh existe no repositório de tokens ativos
  if (!refreshTokensDatabase.has(refreshToken)) {
    return res.status(403).json({
      error: 'Sessão inválida ou expirada. Faça login novamente.'
    });
  }

  try {
    // Decodifica e valida a assinatura do Refresh Token
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);

    // Em produção: Buscar o usuário no banco para garantir que continua ativo e com plano válido
    // const user = await User.findOne({ _id: decoded.userId, tenantId: decoded.tenantId });

    // Rotação de Refresh Token (Good Practice Security):
    // Revoga o token antigo e gera um novo par de tokens
    refreshTokensDatabase.delete(refreshToken);

    const tokens = generateTokens({
      userId: decoded.userId,
      tenantId: decoded.tenantId
    });

    // Registra o novo refresh token
    refreshTokensDatabase.add(tokens.refreshToken);

    return res.status(200).json({
      message: 'Sessão renovada com sucesso.',
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken
    });
  } catch (err) {
    // Se o token estiver corrompido ou expirado, removemos do armazenamento
    refreshTokensDatabase.delete(refreshToken);

    return res.status(403).json({
      error: 'Token de renovação inválido ou expirado.'
    });
  }
});

// ==========================================
// ROTA 2: Encerramento de Sessão (Logout)
// POST /api/auth/logout
// ==========================================
router.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({
      error: 'Token de renovação é obrigatório para encerrar a sessão.'
    });
  }

  // Revoga o refresh token, impedindo novas renovações
  const wasDeleted = refreshTokensDatabase.delete(refreshToken);

  if (!wasDeleted) {
    return res.status(404).json({
      message: 'Sessão já havia sido encerrada ou token inválido.'
    });
  }

  return res.status(200).json({
    message: 'Sessão encerrada com sucesso.'
  });
});

module.exports = router;