const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const router = express.Router();

// Mocks/Interfaces de banco de dados e envio de e-mail (substitua pelos seus ORMs/Serviços)
const db = require('../config/database');
const emailService = require('../services/emailService');

const SALT_ROUNDS = 12;
const TOKEN_EXPIRATION_HOURS = 1;

/**
 * ROTA 1: Solicitação de Redefinição de Senha
 * POST /api/auth/forgot-password
 */
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'O e-mail é obrigatório.' });
    }

    // 1. Busca o usuário no banco de dados com a relação do Tenant (Empresa)
    const user = await db.user.findFirst({
      where: { email: email.toLowerCase().trim() },
      include: { company: true }
    });

    /*
     * MEDIDA DE SEGURANÇA (Timing Attack / Account Enumeration):
     * Se o e-mail não for encontrado, retornamos 200 para evitar que
     * atacantes descubram quais e-mails estão cadastrados na plataforma.
     */
    if (!user) {
      return res.status(200).json({
        message: 'Se o e-mail estiver cadastrado, um link de redefinição será enviado.'
      });
    }

    // 2. Valida se o Tenant (Empresa) possui uma assinatura ativa
    if (user.company.subscriptionStatus !== 'ACTIVE') {
      return res.status(403).json({
        error: 'Acesso suspenso. Entre em contato com o administrador da sua empresa.'
      });
    }

    // 3. Geração do token criptográfico seguro
    const rawToken = crypto.randomBytes(32).toString('hex');

    // 4. Hash do token para armazenamento seguro no banco de dados (SHA-256)
    const resetTokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

    // Define a expiração do token (1 hora a partir do momento atual)
    const expiresAt = new Date(Date.now() + TOKEN_EXPIRATION_HOURS * 3600 * 1000);

    // 5. Invalida tokens anteriores e salva o novo token com isolamento por Tenant
    await db.passwordReset.deleteMany({
      where: { userId: user.id, companyId: user.companyId }
    });

    await db.passwordReset.create({
      data: {
        userId: user.id,
        companyId: user.companyId, // Garantia extra de isolamento do Tenant
        tokenHash: resetTokenHash,
        expiresAt
      }
    });

    // 6. Constrói o link e envia o e-mail ao usuário
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${rawToken}`;

    await emailService.sendMail({
      to: user.email,
      subject: 'Redefinição de Senha - Gestão Empresarial',
      template: 'password-reset',
      context: {
        userName: user.name,
        companyName: user.company.name,
        resetUrl,
        expiresInHours: TOKEN_EXPIRATION_HOURS
      }
    });

    return res.status(200).json({
      message: 'Se o e-mail estiver cadastrado, um link de redefinição será enviado.'
    });

  } catch (error) {
    console.error('Erro na solicitação de redefinição:', error);
    return res.status(500).json({ error: 'Erro interno ao processar a solicitação.' });
  }
});

/**
 * ROTA 2: Confirmação e Redefinição da Senha
 * POST /api/auth/reset-password
 */
router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token e nova senha são obrigatórios.' });
    }

    // Requisito básico de complexidade da senha
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'A senha deve conter no mínimo 8 caracteres.' });
    }

    // 1. Transforma o token recebido no hash esperado pelo banco
    const incomingTokenHash = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    // 2. Busca o registro do token no banco de dados
    const resetRecord = await db.passwordReset.findFirst({
      where: { tokenHash: incomingTokenHash },
      include: {
        user: {
          include: { company: true }
        }
      }
    });

    // Validar se o token existe e se não expirou
    if (!resetRecord || resetRecord.expiresAt < new Date()) {
      return res.status(400).json({ error: 'Token inválido ou expirado.' });
    }

    const { user } = resetRecord;

    // 3. Validação do Tenant na conclusão do fluxo
    if (user.company.subscriptionStatus !== 'ACTIVE') {
      return res.status(403).json({
        error: 'Sua conta/empresa não possui uma assinatura ativa.'
      });
    }

    // 4. Hash da nova senha
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

    // 5. Transação no BD: Atualiza senha e descarta o token de redefinição
    await db.$transaction([
      db.user.update({
        where: { id: user.id },
        data: { password: hashedPassword }
      }),
      db.passwordReset.delete({
        where: { id: resetRecord.id }
      })
    ]);

    return res.status(200).json({
      message: 'Senha alterada com sucesso.'
    });

  } catch (error) {
    console.error('Erro na redefinição de senha:', error);
    return res.status(500).json({ error: 'Erro interno ao redefinir a senha.' });
  }
});

module.exports = router;