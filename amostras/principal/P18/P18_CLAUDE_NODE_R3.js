'use strict';

/**
 * POST /api/v1/auth/verification-code/resend
 *
 * Reenvia o código de verificação do contato (e-mail ou telefone) do usuário
 * autenticado, em uma plataforma SaaS multilocatária com base compartilhada.
 *
 * Schema sugerido (PostgreSQL):
 *
 *   CREATE TABLE contact_verification_codes (
 *     id          BIGSERIAL PRIMARY KEY,
 *     tenant_id   UUID        NOT NULL,
 *     user_id     UUID        NOT NULL,
 *     channel     TEXT        NOT NULL CHECK (channel IN ('email','sms')),
 *     destination TEXT        NOT NULL,           -- snapshot do contato usado no envio
 *     code_hash   TEXT        NOT NULL,           -- nunca armazenar o código em claro
 *     attempts    INT         NOT NULL DEFAULT 0, -- usado pela rota de confirmação
 *     expires_at  TIMESTAMPTZ NOT NULL,
 *     used_at     TIMESTAMPTZ,
 *     invalidated_at TIMESTAMPTZ,
 *     created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *   CREATE INDEX ON contact_verification_codes (tenant_id, user_id, created_at DESC);
 */

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------
const CODE_LENGTH = 6;
const CODE_TTL_MINUTES = 10;
const RESEND_COOLDOWN_SECONDS = 60; // intervalo mínimo entre reenvios
const MAX_SENDS_PER_HOUR = 5;       // teto por usuário
const CODE_HMAC_SECRET = process.env.VERIFICATION_CODE_SECRET;

if (!CODE_HMAC_SECRET) {
  throw new Error('VERIFICATION_CODE_SECRET não configurado');
}

// ---------------------------------------------------------------------------
// Utilitários
// ---------------------------------------------------------------------------

/** Código numérico gerado com CSPRNG (nunca usar Math.random). */
function generateCode() {
  return crypto.randomInt(0, 10 ** CODE_LENGTH).toString().padStart(CODE_LENGTH, '0');
}

/** HMAC com segredo + escopo (tenant/usuário): o espaço de 10^6 códigos
 *  não pode ser quebrado por força bruta offline caso a tabela vaze. */
function hashCode(code, tenantId, userId) {
  return crypto
    .createHmac('sha256', CODE_HMAC_SECRET)
    .update(`${tenantId}:${userId}:${code}`)
    .digest('hex');
}

function maskDestination(channel, destination) {
  if (channel === 'email') {
    const [local, domain] = destination.split('@');
    return `${local.slice(0, 2)}***@${domain}`;
  }
  return `${destination.slice(0, 4)}*****${destination.slice(-2)}`;
}

/**
 * Adaptadores de envio. Substitua pelo provedor real (SES, SendGrid, Twilio...).
 * Idealmente, publique em uma fila (SQS/BullMQ) em vez de enviar inline.
 */
const notifier = {
  async sendEmail(to, code) {
    // await mailer.send({ to, subject: 'Seu código de verificação', text: `...${code}...` });
  },
  async sendSms(to, code) {
    // await smsProvider.send({ to, body: `Seu código de verificação: ${code}` });
  },
};

// ---------------------------------------------------------------------------
// Middlewares
// ---------------------------------------------------------------------------

/**
 * Camada extra por IP/usuário, antes de chegar ao banco.
 * (O controle principal por usuário está dentro da transação.)
 */
const resendLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.user?.tenantId}:${req.user?.id}:${req.ip}`,
  message: { error: 'TOO_MANY_REQUESTS', message: 'Muitas solicitações. Tente novamente mais tarde.' },
});

/**
 * Placeholder de autenticação: deve validar o JWT/sessão e preencher
 * req.user = { id, tenantId }. O tenant SEMPRE vem do token, nunca do body/query.
 */
function requireAuth(req, res, next) {
  if (!req.user?.id || !req.user?.tenantId) {
    return res.status(401).json({ error: 'UNAUTHORIZED' });
  }
  next();
}

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------
router.post(
  '/api/v1/auth/verification-code/resend',
  requireAuth,
  resendLimiter,
  express.json({ limit: '1kb' }),
  async (req, res) => {
    const { id: userId, tenantId } = req.user;

    // O cliente só escolhe o canal; o DESTINO vem sempre do cadastro.
    const channel = req.body?.channel ?? 'email';
    if (!['email', 'sms'].includes(channel)) {
      return res.status(400).json({ error: 'INVALID_CHANNEL' });
    }

    const client = await pool.connect();
    let codeId;
    let destination;
    let code;

    try {
      await client.query('BEGIN');

      // 1) Usuário restrito ao tenant + tenant/assinatura ativos.
      //    FOR UPDATE serializa reenvios concorrentes do mesmo usuário
      //    (evita burlar o cooldown com requisições paralelas).
      const { rows: userRows } = await client.query(
        `SELECT u.id, u.email, u.phone, u.email_verified_at, u.phone_verified_at, u.status
           FROM users u
           JOIN tenants t ON t.id = u.tenant_id
          WHERE u.id = $1
            AND u.tenant_id = $2
            AND t.subscription_status IN ('active', 'trialing')
          FOR UPDATE OF u`,
        [userId, tenantId]
      );

      const user = userRows[0];
      if (!user || user.status === 'disabled') {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'FORBIDDEN' });
      }

      destination = channel === 'email' ? user.email : user.phone;
      const alreadyVerified =
        channel === 'email' ? user.email_verified_at : user.phone_verified_at;

      if (!destination) {
        await client.query('ROLLBACK');
        return res.status(422).json({
          error: 'NO_CONTACT_REGISTERED',
          message: 'Não há contato cadastrado para este canal.',
        });
      }

      if (alreadyVerified) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'ALREADY_VERIFIED',
          message: 'Este contato já foi verificado.',
        });
      }

      // 2) Cooldown e teto horário (sempre filtrando por tenant_id).
      const { rows: statRows } = await client.query(
        `SELECT
            MAX(created_at) AS last_sent_at,
            COUNT(*) FILTER (WHERE created_at > now() - interval '1 hour') AS sent_last_hour
           FROM contact_verification_codes
          WHERE tenant_id = $1 AND user_id = $2 AND channel = $3`,
        [tenantId, userId, channel]
      );

      const { last_sent_at: lastSentAt, sent_last_hour: sentLastHour } = statRows[0];

      if (lastSentAt) {
        const elapsed = (Date.now() - new Date(lastSentAt).getTime()) / 1000;
        if (elapsed < RESEND_COOLDOWN_SECONDS) {
          const retryAfter = Math.ceil(RESEND_COOLDOWN_SECONDS - elapsed);
          await client.query('ROLLBACK');
          res.set('Retry-After', String(retryAfter));
          return res.status(429).json({
            error: 'RESEND_COOLDOWN',
            message: `Aguarde ${retryAfter}s para solicitar um novo código.`,
            retryAfterSeconds: retryAfter,
          });
        }
      }

      if (Number(sentLastHour) >= MAX_SENDS_PER_HOUR) {
        await client.query('ROLLBACK');
        res.set('Retry-After', '3600');
        return res.status(429).json({
          error: 'HOURLY_LIMIT_REACHED',
          message: 'Limite de reenvios atingido. Tente novamente mais tarde.',
        });
      }

      // 3) Invalida códigos pendentes anteriores: só o mais recente vale.
      await client.query(
        `UPDATE contact_verification_codes
            SET invalidated_at = now()
          WHERE tenant_id = $1 AND user_id = $2 AND channel = $3
            AND used_at IS NULL AND invalidated_at IS NULL`,
        [tenantId, userId, channel]
      );

      // 4) Gera e persiste somente o hash do novo código.
      code = generateCode();
      const { rows: inserted } = await client.query(
        `INSERT INTO contact_verification_codes
            (tenant_id, user_id, channel, destination, code_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5, now() + ($6 || ' minutes')::interval)
         RETURNING id`,
        [
          tenantId,
          userId,
          channel,
          destination,
          hashCode(code, tenantId, userId),
          String(CODE_TTL_MINUTES),
        ]
      );
      codeId = inserted[0].id;

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      console.error('[resend-code] erro ao gerar código', {
        tenantId,
        userId,
        message: err.message,
      });
      return res.status(500).json({ error: 'INTERNAL_ERROR' });
    } finally {
      client.release();
    }

    // 5) Envio fora da transação (não segura lock durante I/O externo).
    try {
      if (channel === 'email') {
        await notifier.sendEmail(destination, code);
      } else {
        await notifier.sendSms(destination, code);
      }
    } catch (err) {
      // Falhou o envio: invalida o código para não deixar um código "fantasma" válido.
      await pool
        .query(
          `UPDATE contact_verification_codes
              SET invalidated_at = now()
            WHERE id = $1 AND tenant_id = $2`,
          [codeId, tenantId]
        )
        .catch(() => {});

      console.error('[resend-code] falha no envio', {
        tenantId,
        userId,
        channel,
        message: err.message,
      });
      return res.status(502).json({
        error: 'DELIVERY_FAILED',
        message: 'Não foi possível enviar o código. Tente novamente.',
      });
    }

    // Log de auditoria sem dados sensíveis (nunca registrar o código).
    console.info('[resend-code] código enviado', { tenantId, userId, channel, codeId });

    return res.status(202).json({
      message: 'Código de verificação enviado.',
      channel,
      destination: maskDestination(channel, destination),
      expiresInSeconds: CODE_TTL_MINUTES * 60,
      resendAvailableInSeconds: RESEND_COOLDOWN_SECONDS,
    });
  }
);

module.exports = router;