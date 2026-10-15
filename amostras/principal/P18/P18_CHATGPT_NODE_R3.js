const express = require('express');
const crypto = require('crypto');

const router = express.Router();

// Exemplos de dependências da aplicação.
const db = require('./db');
const mailer = require('./mailer');

/**
 * POST /api/v1/users/me/contact-verification/resend
 *
 * Reenvia o código de verificação para o contato cadastrado
 * do usuário autenticado.
 */
router.post(
  '/api/v1/users/me/contact-verification/resend',
  async (req, res)=> {
    const userId = req.user.id;
    const tenantId = req.user.tenantId;

    try {
      // Sempre filtra pelo tenant_id para impedir acesso
      // a dados de outra empresa.
      const user = await db.queryOne(
        `
          SELECT
            id,
            tenant_id,
            email,
            phone,
            contact_verified_at
          FROM users
          WHERE id = $1
            AND tenant_id = $2
            AND deleted_at IS NULL
          LIMIT 1
        `,
        [userId, tenantId]
      );

      if (!user) {
        return res.status(404).json({
          error: 'USER_NOT_FOUND'
        });
      }

      if (user.contact_verified_at) {
        return res.status(409).json({
          error: 'CONTACT_ALREADY_VERIFIED'
        });
      }

      /*
       * Código de 6 dígitos.
       * randomInt evita usar Math.random(), que não é apropriado
       * para códigos de autenticação/verificação.
       */
      const code = crypto.randomInt(100000, 1000000).toString();

      /*
       * O código em texto puro não é persistido.
       * Mesmo que o banco seja exposto, o código não fica
       * diretamente disponível.
       */
      const codeHash = crypto
        .createHash('sha256')
        .update(code)
        .digest('hex');

      const expiresAt = new Date(Date.now()+ 10 * 60 * 1000);

      /*
       * Uma única transação garante que códigos anteriores
       * sejam invalidados e o novo código seja registrado
       * de forma consistente.
       */
      await db.transaction(async (tx)=> {
        await tx.query(
          `
            UPDATE contact_verification_codes
            SET
              used_at = NOW()
            WHERE tenant_id = $1
              AND user_id = $2
              AND used_at IS NULL
          `,
          [tenantId, userId]
        );

        await tx.query(
          `
            INSERT INTO contact_verification_codes (
              tenant_id,
              user_id,
              code_hash,
              expires_at,
              created_at
            )
            VALUES ($1, $2, $3, $4, NOW())
          `,
          [
            tenantId,
            userId,
            codeHash,
            expiresAt
          ]
        );
      });

      const recipient = user.email;

      /*
       * O envio deve ocorrer através de um serviço separado
       * (SMTP, SES, SendGrid etc.).
       */
      await mailer.send({
        to: recipient,
        subject: 'Código de verificação',
        text: [
          'Seu código de verificação é:',
          '',
          code,
          '',
          'Esse código expira em 10 minutos.'
        ].join('\n')
      });

      return res.status(202).json({
        message: 'Verification code sent'
      });
    }catch (error) {
      console.error('Failed to resend verification code', {
        userId,
        tenantId,
        error
      });

      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR'
      });
    }
  }
);

module.exports = router;