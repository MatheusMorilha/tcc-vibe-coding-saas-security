const express = require('express');
const crypto = require('crypto');

const router = express.Router();

/**
 * Utilitário para gerar um código numérico seguro de 6 dígitos
 */
function generateVerificationCode(){
  const min = 100000;
  const max = 999999;
  return crypto.randomInt(min, max + 1).toString();
}

/**
 * Utilitário para criar hash do código antes de persistir na base
 */
function hashCode(code){
  return crypto.createHash('sha256').update(code).digest('hex');
}

/**
 * POST /api/v1/auth/resend-verification
 * Rota responsável por reenviar o código de confirmação
 */
router.post('/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;

    // O tenantId deve vir do contexto de autenticação ou da resolução do subdomínio/header
    const tenantId = req.tenantId || req.headers['x-tenant-id'];

    if (!email || !tenantId) {
      return res.status(400).json({
        error: 'BAD_REQUEST',
        message: 'O e-mail e o identificador da empresa (tenantId) são obrigatórios.'
      });
    }

    // 1. Busca o usuário isolando estritamente pelo Tenant
    const user = await db.user.findFirst({
      where: {
        email: email.toLowerCase().trim(),
        tenantId: tenantId
      }
    });

    // Segurança: Resposta genérica mesmo se o usuário não for encontrado para evitar enumeration attacks
    if (!user) {
      return res.status(200).json({
        message: 'Se o cadastro existir e ainda não estiver verificado, um novo código será enviado.'
      });
    }

    // Se o usuário já estiver verificado, não há necessidade de reenviar o código
    if (user.isVerified) {
      return res.status(400).json({
        error: 'ALREADY_VERIFIED',
        message: 'Este contato já se encontra confirmado.'
      });
    }

    // 2. Rate Limiting: Impede novos envios se um código foi gerado nos últimos 60 segundos
    const COOLDOWN_IN_SECONDS = 60;
    if (user.verificationCodeSentAt) {
      const secondsSinceLastSend = (Date.now() - new Date(user.verificationCodeSentAt).getTime()) / 1000;
      if (secondsSinceLastSend < COOLDOWN_IN_SECONDS) {
        const waitTime = Math.ceil(COOLDOWN_IN_SECONDS - secondsSinceLastSend);
        return res.status(429).json({
          error: 'TOO_MANY_REQUESTS',
          message: `Aguarde ${waitTime} segundo(s) para solicitar um novo código.`
        });
      }
    }

    // 3. Geração de novo código e expiração (válido por 15 minutos)
    const rawCode = generateVerificationCode();
    const codeHash = hashCode(rawCode);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    // 4. Atualização atômica do usuário na base de dados
    await db.user.update({
      where: { id: user.id },
      data: {
        verificationCodeHash: codeHash,
        verificationCodeExpiresAt: expiresAt,
        verificationCodeSentAt: new Date()
      }
    });

    // 5. Disparo do evento de envio do e-mail/notificação (Async)
    // Exemplo usando uma fila/serviço de mensageria
    await emailService.sendVerificationCode({
      to: user.email,
      name: user.name,
      code: rawCode,
      tenantId: tenantId
    });

    return res.status(200).json({
      message: 'Se o cadastro existir e ainda não estiver verificado, um novo código será enviado.'
    });

  } catch (error) {
    console.error('[ResendVerificationError]:', error);
    return res.status(500).json({
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Ocorreu um erro interno ao processar a solicitação.'
    });
  }
});

module.exports = router;