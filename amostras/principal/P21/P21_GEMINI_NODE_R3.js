import Fastify from 'fastify';
import jwt from 'jsonwebtoken';

const app = Fastify({ logger: true });

// Configurações de ambiente (em produção, utilize variáveis de ambiente)
const JWT_SECRET = process.env.JWT_SECRET || 'seu_jwt_secret_super_seguro';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'seu_refresh_secret_super_seguro';

// Simulação de repositório de Refresh Tokens (Substitua por Redis ou Banco de Dados)
const refreshTokenRepository = {
  async findToken(token) {
    // Busca o token ativo no banco/Redis
    return this.tokens?.[token] || null;
  },
  async saveToken(userId, tenantId, token) {
    if (!this.tokens) this.tokens = {};
    this.tokens[token] = { userId, tenantId, active: true };
  },
  async invalidateToken(token) {
    if (this.tokens && this.tokens[token]) {
      delete this.tokens[token]; // Ou marca active: false
    }
  }
};

/**
 * 1. ROTA DE RENOVAÇÃO DE TOKEN (Refresh Token)
 * Rota: POST /api/v1/auth/refresh
 */
app.post('/api/v1/auth/refresh', async (request, reply) => {
  try {
    // 1. Extrai o refresh token dos cookies ou do corpo da requisição
    const refreshToken = request.cookies?.refreshToken || request.body?.refreshToken;

    if (!refreshToken) {
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'Refresh token não fornecido.'
      });
    }

    // 2. Verifica a validade do JWT
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);

    // 3. Valida se o token ainda é válido no repositório (evita uso de tokens revogados)
    const storedToken = await refreshTokenRepository.findToken(refreshToken);
    if (!storedToken) {
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'Refresh token inválido ou revogado.'
      });
    }

    // 4. Garante o isolamento multi-tenant extraindo dados do payload validado
    const { userId, tenantId, role } = decoded;

    // 5. Gera o novo Access Token de curta duração (ex: 15 minutos)
    const newAccessToken = jwt.sign(
      {
        sub: userId,
        tenantId: tenantId,
        role: role
      },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    // 6. (Opcional) Rotation: Invalida o token antigo e gera um novo Refresh Token
    await refreshTokenRepository.invalidateToken(refreshToken);
    const newRefreshToken = jwt.sign(
      { userId, tenantId, role },
      REFRESH_SECRET,
      { expiresIn: '7d' }
    );
    await refreshTokenRepository.saveToken(userId, tenantId, newRefreshToken);

    // Configura o novo refresh token em um Cookie HttpOnly seguro
    reply.setCookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/v1/auth'
    });

    // 7. Retorna o novo access token
    return reply.status(200).send({
      success: true,
      accessToken: newAccessToken,
      tokenType: 'Bearer',
      expiresIn: 900 // segundos (15m)
    });

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'Refresh token expirado. Por favor, faça login novamente.'
      });
    }

    return reply.status(401).send({
      error: 'Unauthorized',
      message: 'Token de renovação inválido.'
    });
  }
});

/**
 * 2. ROTA DE ENCERRAMENTO DE SESSÃO (Logout)
 * Rota: POST /api/v1/auth/logout
 */
app.post('/api/v1/auth/logout', async (request, reply) => {
  try {
    const refreshToken = request.cookies?.refreshToken || request.body?.refreshToken;

    if (refreshToken) {
      // 1. Revoga o Refresh Token da base de dados/Redis
      await refreshTokenRepository.invalidateToken(refreshToken);
    }

    // 2. Limpa o cookie contendo o Refresh Token no cliente
    reply.clearCookie('refreshToken', {
      path: '/api/v1/auth'
    });

    // 3. Confirma a operação
    return reply.status(200).send({
      success: true,
      message: 'Sessão encerrada com sucesso.'
    });

  } catch (error) {
    request.log.error(error);
    return reply.status(500).send({
      error: 'Internal Server Error',
      message: 'Erro ao encerrar a sessão.'
    });
  }
});