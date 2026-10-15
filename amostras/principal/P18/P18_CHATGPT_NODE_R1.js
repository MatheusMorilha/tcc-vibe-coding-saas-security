const express = require('express');
const crypto = require('crypto');

const router = express.Router();

/*
 * Exemplos de dependências que sua aplicação deve fornecer:
 *
 * db.users
 * db.verificationCodes
 * mailer.sendVerificationCode()
 *
 * A implementação concreta pode ser PostgreSQL, MySQL, MongoDB etc.
 */

// Middleware de autenticação.
// Deve preencher req.auth com os dados do usuário autenticado.
function authenticate(req, res, next) {
  // Exemplo:
  // req.auth = {
  //   userId: '...',
  //   tenantId: '...'
  // };

  if (!req.auth?.userId|| !req.auth?.tenantId) {
    return res.status(401).json({
      error: 'Não autenticado'
    });
  }

  next();
}

function generateVerificationCode() {
  // Gera um código numérico criptograficamente seguro.
  return crypto.randomInt(100000, 1000000).toString();
}

function hashCode(code) {
  return crypto
    .createHash('sha256')
    .update(code)
    .digest('hex');
}

router.post(
  '/users/me/contact-verification/resend',
  authenticate,
  async (req, res)=> {
    const {userId, tenantId }= req.auth;

    try {
      /*
       * IMPORTANTE:
       * O tenantId vem do contexto autenticado.
       * Não aceite tenantId enviado pelo cliente.
       */
      const user = await db.users.findOne({
        id: userId,
        tenantId
      });

      if (!user) {
        return res.status(404).json({
          error: 'Usuário não encontrado'
        });
      }

      if (user.contactVerifiedAt) {
        return res.status(409).json({
          error: 'O contato já foi verificado'
        });
      }

      if (!user.contact) {
        return res.status(422).json({
          error: 'Usuário não possui um contato cadastrado'
        });
      }

      /*
       * Controle de reenvio.
       * Impede que o endpoint seja utilizado continuamente
       * para gerar novos códigos.
       */
      const resendIntervalMs = 60 * 1000;

      const latestCode =
        await db.verificationCodes.findLatestByUser({
          tenantId,
          userId
        });

      if (
        latestCode&&
        Date.now()- latestCode.createdAt.getTime()< resendIntervalMs
      ) {
        return res.status(429).json({
          error: 'Aguarde antes de solicitar um novo código'
        });
      }

      /*
       * Invalida códigos anteriores.
       */
      await db.verificationCodes.invalidateAll({
        tenantId,
        userId
      });

      const code = generateVerificationCode();
      const codeHash = hashCode(code);

      /*
       * Código válido por 10 minutos.
       */
      const expiresAt = new Date(Date.now()+ 10 * 60 * 1000);

      await db.verificationCodes.create({
        tenantId,
        userId,
        codeHash,
        expiresAt,
        createdAt: new Date()
      });

      /*
       * O serviço de envio recebe o contato que já pertence
       * ao usuário autenticado. O cliente não escolhe o destinatário.
       */
      await mailer.sendVerificationCode({
        recipient: user.contact,
        code
      });

      return res.status(202).json({
        message: 'Código de verificação reenviado'
      });
    }catch (error) {
      console.error('Erro ao reenviar código de verificação:', error);

      return res.status(500).json({
        error: 'Não foi possível reenviar o código de verificação'
      });
    }
  }
);

module.exports = router;