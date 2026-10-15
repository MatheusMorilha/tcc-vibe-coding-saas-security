const crypto = require('crypto');
const bcrypt = require('bcrypt');

/**
 * Gera um token randômico para o usuário e o seu respectivo hash criptográfico
 * para armazenamento seguro no banco de dados.
 */
function generateResetToken(){
  const unhashedToken = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto
    .createHash('sha256')
    .update(unhashedToken)
    .digest('hex');

  return { unhashedToken, hashedToken };
}

/**
 * Envia o e-mail com o link de redefinição contendo o token não-hash.
 */
async function sendPasswordResetEmail(email, token){
  const resetUrl = `https://app.suaplataforma.com/reset-password?token=${token}`;

  // Exemplo de integração com serviço de e-mail (SendGrid, AWS SES, Resend, etc.)
  console.log(`[EMAIL SENT] Para: ${email} | Link: ${resetUrl}`);
}

module.exports = {
  generateResetToken,
  sendPasswordResetEmail,
};

const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const { generateResetToken, sendPasswordResetEmail } = require('./authUtils');

const router = express.Router();
const prisma = new PrismaClient();

const SALT_ROUNDS = 12;
const TOKEN_EXPIRATION_MINUTES = 30;

/**
 * ROTA 1: Solicitação de Redefinição de Senha
 * POST /api/v1/auth/forgot-password
 */
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'O e-mail é obrigatório.' });
    }

    // Busca o usuário garantindo que a empresa/tenant associada esteja ativa
    const user = await prisma.user.findFirst({
      where: {
        email: email.toLowerCase().trim(),
        company: {
          subscriptionStatus: 'ACTIVE',
        },
      },
    });

    // Medida de segurança (Timing Attack / User Enumeration):
    // Sempre retorne a mesma mensagem genérica, existindo ou não o e-mail na base.
    if (!user) {
      return res.status(200).json({
        message: 'Se o e-mail estiver cadastrado em nossa base, você receberá as instruções para redefinição.',
      });
    }

    // Gera o token puro (enviado por e-mail) e o hash (salvo no banco)
    const { unhashedToken, hashedToken } = generateResetToken();
    const expiresAt = new Date(Date.now() + TOKEN_EXPIRATION_MINUTES * 60 * 1000);

    // Salva o hash e a expiração no registro do usuário
    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: hashedToken,
        passwordResetExpiresAt: expiresAt,
      },
    });

    // Dispara o e-mail de forma assíncrona
    await sendPasswordResetEmail(user.email, unhashedToken);

    return res.status(200).json({
      message: 'Se o e-mail estiver cadastrado em nossa base, você receberá as instruções para redefinição.',
    });
  } catch (error) {
    console.error('Erro na solicitação de redefinição de senha:', error);
    return res.status(500).json({ error: 'Erro interno ao processar a solicitação.' });
  }
});

/**
 * ROTA 2: Conclusão da Redefinição de Senha
 * POST /api/v1/auth/reset-password
 */
router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token e nova senha são obrigatórios.' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'A senha deve conter no mínimo 8 caracteres.' });
    }

    // Recria o hash a partir do token recebido na requisição para buscar no banco
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    // Localiza o usuário correspondente ao token dentro do prazo de validade
    const user = await prisma.user.findFirst({
      where: {
        passwordResetToken: hashedToken,
        passwordResetExpiresAt: {
          gt: new Date(), // Garante que token não expirou
        },
      },
    });

    if (!user) {
      return res.status(400).json({ error: 'Token inválido ou expirado.' });
    }

    // Gera o hash da nova senha
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

    // Atualiza a senha e invalida o token utilizado em uma única transação
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        passwordResetToken: null,
        passwordResetExpiresAt: null,
      },
    });

    return res.status(200).json({ message: 'Senha alterada com sucesso.' });
  } catch (error) {
    console.error('Erro ao redefinir a senha:', error);
    return res.status(500).json({ error: 'Erro interno ao redefinir a senha.' });
  }
});

module.exports = router;