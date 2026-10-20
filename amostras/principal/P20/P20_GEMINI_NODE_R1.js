const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
// Exemplo de ORM (Prisma/Sequelize) ou Pool de Conexão simulado
const { db } = require('./database'); 
const { sendEmail } = require('./emailService');

const router = express.Router();

/**
 * 1. Solicitação de Recuperação de Senha
 * Recebe o e-mail, gera um token seguro com expiração e envia o link/token por e-mail.
 * Utiliza o conceito de tenant isolado na mesma base (filtrando por e-mail ou buscando o usuário globalmente se único).
 */
router.post('/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'O campo e-mail é obrigatório.' });
    }

    // Busca o usuário na base compartilhada (multitenant)
    const user = await db.user.findUnique({ where: { email } });

    // Por segurança, evitamos expor se o e-mail existe ou não na base
    if (!user) {
      return res.status(200).json({ 
        message: 'Se o e-mail estiver cadastrado, você receberá as instruções de redefinição.' 
      });
    }

    // Gera um token aleatório seguro
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    // Hash do token para salvar no banco (boa prática de segurança)
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    
    // Define expiração para 1 hora
    const tokenExpiration = new Date(Date.now() + 60 * 60 * 1000);

    // Salva o token e a expiração no registro do usuário (mantendo o contexto do tenant)
    await db.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: hashedToken,
        passwordResetExpires: tokenExpiration,
      },
    });

    // Simula o link enviado por e-mail (em produção, usar variável de ambiente para o domínio)
    const resetUrl = `https://app.suaplataforma.com/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`;

    await sendEmail({
      to: user.email,
      subject: 'Redefinição de Senha - Gestão Empresarial',
      html: `<p>Você solicitou a redefinição de senha. Clique no link abaixo para prosseguir:</p><a href="${resetUrl}">${resetUrl}</a><p>Este link expira em 1 hora.</p>`
    });

    return res.status(200).json({ 
      message: 'Se o e-mail estiver cadastrado, você receberá as instruções de redefinição.' 
    });

  } catch (error) {
    console.error('Erro no forgot-password:', error);
    return res.status(500).json({ error: 'Erro interno no servidor. Tente novamente mais tarde.' });
  }
});

/**
 * 2. Conclusão da Alteração de Senha
 * Recebe o token enviado por e-mail e a nova senha, valida a expiração e atualiza o hash da senha.
 */
router.post('/auth/reset-password', async (req, res) => {
  try {
    const { token, email, newPassword } = req.body;

    if (!token || !email || !newPassword) {
      return res.status(400).json({ error: 'Token, e-mail e nova senha são obrigatórios.' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'A nova senha deve ter no mínimo 8 caracteres.' });
    }

    // Hash do token recebido para comparar com o armazenado no banco
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Busca o usuário considerando o tenant implícito pelo e-mail e validando o token e sua validade
    const user = await db.user.findFirst({
      where: {
        email,
        passwordResetToken: hashedToken,
        passwordResetExpires: { gt: new Date() }, // Verifica se não expirou
      },
    });

    if (!user) {
      return res.status(400).json({ error: 'Token inválido ou expirado.' });
    }

    // Gera o hash da nova senha
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Atualiza a senha, limpa os campos de recuperação e garante integridade do tenant
    await db.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        passwordResetToken: null,
        passwordResetExpires: null,
      },
    });

    return res.status(200).json({ message: 'Senha alterada com sucesso.' });

  } catch (error) {
    console.error('Erro no reset-password:', error);
    return res.status(500).json({ error: 'Erro interno no servidor. Tente novamente mais tarde.' });
  }
});

module.exports = router;