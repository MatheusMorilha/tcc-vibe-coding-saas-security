const express = require('express');
const crypto = require('crypto');
const router = express.Router();

// Exemplo de utilitários (substitua pelas integrações/modelos reais do seu projeto)
const { User, VerificationCode } = require('../models');
const { sendVerificationEmail, sendVerificationSMS } = require('../services/notificationService');

/**
 * POST /api/v1/auth/resend-verification
 * Reenvia o código de verificação para confirmação de contato do usuário.
 */
router.post('/resend-verification', async (req, res) => {
  try {
    const { userId, tenantId, contactType } = req.body;

    // 1. Validação básica de entrada
    if (!userId || !tenantId) {
      return res.status(400).json({
        error: 'ID do usuário e ID do tenant são obrigatórios.'
      });
    }

    const type = contactType || 'email'; // 'email' ou 'phone'
    if (!['email', 'phone'].includes(type)) {
      return res.status(400).json({
        error: 'Tipo de contato inválido. Use "email" ou "phone".'
      });
    }

    // 2. Busca o usuário garantindo o isolamento multi-tenant (tenant_id)
    const user = await User.findOne({
      where: {
        id: userId,
        tenantId: tenantId
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado para este tenant.' });
    }

    // Verifica se o contato já foi validado
    const isAlreadyVerified = type === 'email' ? user.isEmailVerified : user.isPhoneVerified;
    if (isAlreadyVerified) {
      return res.status(400).json({ error: `Este ${type} já foi verificado.` });
    }

    // 3. Controla Rate Limiting para prevenir abuso de reenvio (ex: janela de 1 minuto)
    const lastCode = await VerificationCode.findOne({
      where: { userId, tenantId, type },
      order: [['createdAt', 'DESC']]
    });

    if (lastCode) {
      const secondsSinceLastSend = (Date.now() - new Date(lastCode.createdAt).getTime()) / 1000;
      if (secondsSinceLastSend < 60) {
        const waitSeconds = Math.ceil(60 - secondsSinceLastSend);
        return res.status(429).json({
          error: `Aguarde ${waitSeconds} segundos antes de solicitar um novo código.`
        });
      }
    }

    // 4. Gera código numérico seguro de 6 dígitos
    const codeBuffer = crypto.randomInt(100000, 999999);
    const rawCode = codeBuffer.toString();

    // Gera Hash do código para armazenar de forma segura no banco de dados
    const hashCode = crypto.createHash('sha256').update(rawCode).digest('hex');

    // Define expiração (ex: 15 minutos)
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    // 5. Invalida códigos anteriores e salva o novo no banco
    await VerificationCode.update(
      { status: 'invalidated' },
      { where: { userId, tenantId, type, status: 'pending' } }
    );

    await VerificationCode.create({
      tenantId,
      userId,
      codeHash: hashCode,
      type,
      status: 'pending',
      expiresAt
    });

    // 6. Dispara o envio ao destinatário cadastrado
    const recipient = type === 'email' ? user.email : user.phoneNumber;

    if (type === 'email') {
      await sendVerificationEmail({
        to: recipient,
        code: rawCode,
        userName: user.name
      });
    } else {
      await sendVerificationSMS({
        to: recipient,
        code: rawCode
      });
    }

    return res.status(200).json({
      message: `Código de verificação reenviado com sucesso para o ${type} cadastrado.`,
      expiresAt
    });

  } catch (error) {
    console.error('[ResendVerificationError]:', error);
    return res.status(500).json({
      error: 'Erro interno ao processar o reenvio do código.'
    });
  }
});

module.exports = router;