const express = require('express');
const crypto = require('crypto');
const router = express.Router();

// Exemplo de serviço de email/SMS fictício
const notificationService = require('../services/notificationService');
// Repositórios/Models da aplicação
const { User, VerificationCode } = require('../models');

/**
 * Gera um código numérico de 6 dígitos seguro
 */
function generateVerificationCode(){
  return crypto.randomInt(100000, 999999).toString();
}

/**
 * POST /api/v1/auth/resend-verification-code
 *
 * Reenvia o código de verificação para o usuário.
 * Espera `tenantId` e `email` ou `userId` no corpo ou contexto da requisição.
 */
router.post('/resend-verification-code', async (req, res) => {
  try {
    const { email, tenantId } = req.body;

    // 1. Validação dos dados de entrada
    if (!email || !tenantId) {
      return res.status(400).json({
        error: 'BAD_REQUEST',
        message: 'O email e o tenantId são obrigatórios.'
      });
    }

    // 2. Busca o usuário garantindo o isolamento multilocatário (Tenant Isolation)
    const user = await User.findOne({
      where: {
        email: email.toLowerCase().trim(),
        tenantId: tenantId
      }
    });

    // Por razões de segurança (evitar enumeração de usuários), retorne 200 mesmo se não encontrar
    if (!user) {
      return res.status(200).json({
        message: 'Se as informações estiverem corretas, um novo código será enviado.'
      });
    }

    // 3. Verifica se o usuário já possui o contato verificado
    if (user.isVerified) {
      return res.status(400).json({
        error: 'ALREADY_VERIFIED',
        message: 'Este contato já se encontra verificado.'
      });
    }

    // 4. Rate Limiting: Verifica se um código recente já foi enviado (ex: nos últimos 60 segundos)
    const recentCode = await VerificationCode.findOne({
      where: {
        userId: user.id,
        tenantId: user.tenantId,
        createdAt: { $gte: new Date(Date.now() - 60 * 1000) } // Criado há menos de 1 minuto
      }
    });

    if (recentCode) {
      return res.status(429).json({
        error: 'TOO_MANY_REQUESTS',
        message: 'Aguarde 1 minuto antes de solicitar um novo código.'
      });
    }

    // 5. Invalida/deleta códigos anteriores ativos do usuário
    await VerificationCode.update(
      { active: false },
      { where: { userId: user.id, tenantId: user.tenantId, active: true } }
    );

    // 6. Gera novo código e define expiração (ex: 15 minutos)
    const code = generateVerificationCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await VerificationCode.create({
      userId: user.id,
      tenantId: user.tenantId,
      code: code, // Recomenda-se armazenar o hash do código no DB em produção
      expiresAt: expiresAt,
      active: true
    });

    // 7. Dispara o envio ao destinatário (E-mail ou SMS)
    await notificationService.sendVerificationCode({
      to: user.email,
      name: user.name,
      code: code,
      tenantId: user.tenantId
    });

    // 8. Resposta de sucesso (nunca retorne o código gerado no JSON)
    return res.status(200).json({
      message: 'Novo código de verificação enviado com sucesso.'
    });

  } catch (error) {
    console.error('[ResendVerificationCodeError]:', error);
    return res.status(500).json({
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Ocorreu um erro ao reenviar o código de verificação.'
    });
  }
});

module.exports = router;