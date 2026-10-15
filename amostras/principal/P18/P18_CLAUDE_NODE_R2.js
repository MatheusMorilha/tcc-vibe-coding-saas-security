// routes/resendVerificationCode.js
'use strict';

const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { pool } = require('../db');                       // pg.Pool
const { authenticate } = require('../middlewares/auth'); // popula req.user = { id, tenantId }
const { sendEmail, sendSms } = require('../services/notifier');
const logger = require('../logger');

const router = express.Router();

/*
  Esquema esperado (resumo):

  users(id, tenant_id, name, email, phone, contact_verified_at, ...)
  tenants(id, subscription_status)             -- 'active' | 'past_due' | 'canceled' ...
  verification_codes(
    id uuid pk, tenant_id, user_id, channel, destination,
    code_hash text, expires_at timestamptz, attempts int default 0,
    consumed_at timestamptz null, created_at timestamptz default now()
  )
  CREATE INDEX ON verification_codes (tenant_id, user_id, created_at DESC);
*/

const CODE_TTL_MINUTES = 10;
const COOLDOWN_SECONDS = 60;      // intervalo mínimo entre reenvios
const MAX_SENDS_PER_HOUR = 5;     // limite por usuário
const CODE_SECRET = process.env.VERIFICATION_CODE_SECRET; // obrigatório

if (!CODE_SECRET) throw new Error('VERIFICATION_CODE_SECRET não configurado');

// Limite por IP (camada extra, antes de tocar no banco)
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'TOO_MANY_REQUESTS', message: 'Muitas tentativas. Tente mais tarde.' },
});

// Código numérico de 6 dígitos gerado com CSPRNG (nunca Math.random)
function generateCode() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
}

// Armazenamos apenas o HMAC do código, vinculado ao tenant e ao usuário
function hashCode(code, tenantId, userId) {
  return crypto
    .createHmac('sha256', CODE_SECRET)
    .update(`${tenantId}:${userId}:${code}`)
    .digest('hex');
}

function maskDestination(channel, value) {
  if (channel === 'email') {
    const [local, domain] = value.split('@');
    return `${local.slice(0, 2)}***@${domain}`;
  }
  return `${'*'.repeat(Math.max(value.length - 4, 0))}${value.slice(-4)}`;
}

router.post(
  '/auth/verification-code/resend',
  ipLimiter,
  authenticate,
  async (req, res) => {
    // Identidade e tenant vêm SEMPRE do token/sessão, nunca do body
    const { id: userId, tenantId } = req.user;

    // O body só pode escolher o canal; o destino é sempre o cadastrado
    const requested = req.body?.channel;
    if (requested !== undefined && !['email', 'sms'].includes(requested)) {
      return res.status(400).json({ error: 'INVALID_CHANNEL' });
    }

    const client = await pool.connect();
    let codeId;
    let channel;
    let destination;
    let userName;
    let code;

    try {
      await client.query('BEGIN');

      // Trava a linha do usuário para evitar corrida entre reenvios simultâneos.
      // Filtro por tenant_id garante o isolamento multilocatário.
      const { rows: [user] } = await client.query(
        `SELECT u.id, u.name, u.email, u.phone, u.contact_verified_at,
                t.subscription_status
           FROM users u
           JOIN tenants t ON t.id = u.tenant_id
          WHERE u.id = $1 AND u.tenant_id = $2
          FOR UPDATE OF u`,
        [userId, tenantId]
      );

      if (!user) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'USER_NOT_FOUND' });
      }

      if (user.subscription_status !== 'active') {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'SUBSCRIPTION_INACTIVE' });
      }

      if (user.contact_verified_at) {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'ALREADY_VERIFIED' });
      }

      channel = requested || (user.email ? 'email' : 'sms');
      destination = channel === 'email' ? user.email : user.phone;
      userName = user.name;

      if (!destination) {
        await client.query('ROLLBACK');
        return res.status(422).json({ error: 'NO_CONTACT_REGISTERED' });
      }

      // Cooldown e limite horário (consultas sob o lock do usuário)
      const { rows: [stats] } = await client.query(
        `SELECT
           COUNT(*) FILTER (WHERE created_at > now() - interval '1 hour')::int AS last_hour,
           EXTRACT(EPOCH FROM (now() - MAX(created_at)))::int AS seconds_since_last
           FROM verification_codes
          WHERE tenant_id = $1 AND user_id = $2`,
        [tenantId, userId]
      );

      if (stats.seconds_since_last !== null && stats.seconds_since_last < COOLDOWN_SECONDS) {
        await client.query('ROLLBACK');
        const retryAfter = COOLDOWN_SECONDS - stats.seconds_since_last;
        res.set('Retry-After', String(retryAfter));
        return res.status(429).json({ error: 'COOLDOWN_ACTIVE', retryAfterSeconds: retryAfter });
      }

      if (stats.last_hour >= MAX_SENDS_PER_HOUR) {
        await client.query('ROLLBACK');
        res.set('Retry-After', '3600');
        return res.status(429).json({ error: 'HOURLY_LIMIT_REACHED' });
      }

      // Invalida códigos anteriores ainda válidos (só o mais recente funciona)
      await client.query(
        `UPDATE verification_codes
            SET consumed_at = now()
          WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL`,
        [tenantId, userId]
      );

      code = generateCode();
      const { rows: [created] } = await client.query(
        `INSERT INTO verification_codes
           (id, tenant_id, user_id, channel, destination, code_hash, expires_at)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5,
                 now() + ($6 || ' minutes')::interval)
         RETURNING id`,
        [tenantId, userId, channel, destination, hashCode(code, tenantId, userId), CODE_TTL_MINUTES]
      );
      codeId = created.id;

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      logger.error({ err, tenantId, userId }, 'Falha ao gerar código de verificação');
      return res.status(500).json({ error: 'INTERNAL_ERROR' });
    } finally {
      client.release();
    }

    // Envio fora da transação: não segura lock durante I/O de rede
    try {
      if (channel === 'email') {
        await sendEmail({
          to: destination,
          subject: 'Seu código de verificação',
          text: `Olá, ${userName}. Seu código é ${code}. Ele expira em ${CODE_TTL_MINUTES} minutos.`,
        });
      } else {
        await sendSms({
          to: destination,
          message: `Seu código de verificação: ${code}. Expira em ${CODE_TTL_MINUTES} min.`,
        });
      }
    } catch (err) {
      // Se o envio falhou, invalida o código para não deixar lixo utilizável
      await pool
        .query(
          `UPDATE verification_codes SET consumed_at = now()
            WHERE id = $1 AND tenant_id = $2`,
          [codeId, tenantId]
        )
        .catch(() => {});
      logger.error({ err, tenantId, userId, channel }, 'Falha ao enviar código de verificação');
      return res.status(502).json({ error: 'DELIVERY_FAILED' });
    }

    // Auditoria sem registrar o código
    logger.info({ tenantId, userId, channel, codeId }, 'Código de verificação reenviado');

    // O código NUNCA é devolvido na resposta
    return res.status(202).json({
      message: 'Código de verificação enviado.',
      channel,
      destination: maskDestination(channel, destination),
      expiresInSeconds: CODE_TTL_MINUTES * 60,
      resendAvailableInSeconds: COOLDOWN_SECONDS,
    });
  }
);

module.exports = router;