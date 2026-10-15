'use strict';

/**
 * POST /api/v1/contact-verification/resend
 *
 * Reenvia o código de verificação do contato (e-mail ou telefone) do
 * usuário autenticado.
 *
 * Decisões de segurança:
 *  - tenantId e userId vêm SEMPRE do token autenticado, nunca do body/query.
 *  - O destino é SEMPRE o contato cadastrado; o cliente não informa para onde enviar.
 *  - Toda consulta é filtrada por tenant_id (isolamento lógico na base compartilhada).
 *  - Código gerado com CSPRNG e armazenado apenas como HMAC (nunca em texto puro).
 *  - Cooldown + limite por hora por usuário + rate limit por IP.
 *  - Códigos anteriores pendentes são invalidados (apenas o mais recente vale).
 *  - Linha do usuário bloqueada (FOR UPDATE) para evitar corrida em requisições simultâneas.
 *  - O código nunca é logado nem devolvido na resposta.
 *
 * Esquema esperado (PostgreSQL):
 *
 *   CREATE TABLE tenants (
 *     id UUID PRIMARY KEY,
 *     subscription_status TEXT NOT NULL            -- 'active', 'past_due', 'canceled'...
 *   );
 *
 *   CREATE TABLE users (
 *     id UUID PRIMARY KEY,
 *     tenant_id UUID NOT NULL REFERENCES tenants(id),
 *     email TEXT,
 *     phone TEXT,
 *     email_verified_at TIMESTAMPTZ,
 *     phone_verified_at TIMESTAMPTZ
 *   );
 *
 *   CREATE TABLE contact_verification_codes (
 *     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 *     tenant_id UUID NOT NULL,
 *     user_id UUID NOT NULL,
 *     channel TEXT NOT NULL CHECK (channel IN ('email','sms')),
 *     code_hash TEXT NOT NULL,
 *     attempts INT NOT NULL DEFAULT 0,
 *     expires_at TIMESTAMPTZ NOT NULL,
 *     consumed_at TIMESTAMPTZ,
 *     invalidated_at TIMESTAMPTZ,
 *     created_at TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *   CREATE INDEX ON contact_verification_codes (tenant_id, user_id, channel, created_at DESC);
 */

const crypto = require('node:crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

// ----------------------------------------------------------------------------
// Configuração
// ----------------------------------------------------------------------------
const CODE_LENGTH = 6;
const CODE_TTL_MS = 10 * 60 * 1000;        // validade do código: 10 min
const RESEND_COOLDOWN_MS = 60 * 1000;      // intervalo mínimo entre reenvios: 60 s
const MAX_SENDS_PER_HOUR = 5;              // máximo de códigos por usuário/canal/hora

const CODE_HMAC_SECRET = process.env.VERIFICATION_CODE_HMAC_SECRET;
if (!CODE_HMAC_SECRET || CODE_HMAC_SECRET.length < 32) {
  throw new Error('VERIFICATION_CODE_HMAC_SECRET ausente ou curto (mín. 32 caracteres).');
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ----------------------------------------------------------------------------
// Dependências externas (injete as suas implementações reais)
// ----------------------------------------------------------------------------
// Devem lançar erro em caso de falha no provedor.
const notifier = {
  async sendEmail({ to, code, expiresInMinutes }) {
    // ex.: SES, SendGrid, Resend...
    throw new Error('Implementar provedor de e-mail');
  },
  async sendSms({ to, code, expiresInMinutes }) {
    // ex.: Twilio, Zenvia...
    throw new Error('Implementar provedor de SMS');
  },
};

// Middleware de autenticação: deve preencher req.auth = { userId, tenantId }
// a partir de um JWT/sessão VALIDADOS no servidor.
const authenticate = (req, res, next) => {
  // ... implementação real
  next();
};

// ----------------------------------------------------------------------------
// Utilitários
// ----------------------------------------------------------------------------
function generateNumericCode(length = CODE_LENGTH) {
  // crypto.randomInt é uniforme e criptograficamente seguro (sem viés de módulo).
  return String(crypto.randomInt(0, 10 ** length)).padStart(length, '0');
}

function hashCode({ tenantId, userId, channel, code }) {
  // HMAC com segredo + contexto: impede reuso do hash entre usuários/tenants.
  return crypto
    .createHmac('sha256', CODE_HMAC_SECRET)
    .update(`${tenantId}:${userId}:${channel}:${code}`)
    .digest('hex');
}

function maskEmail(email) {
  const [local, domain] = email.split('@');
  return `${local.slice(0, 2)}${'*'.repeat(Math.max(local.length - 2, 1))}@${domain}`;
}

function maskPhone(phone) {
  return `${'*'.repeat(Math.max(phone.length - 4, 0))}${phone.slice(-4)}`;
}

class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

// ----------------------------------------------------------------------------
// Rate limit por IP (camada extra; o controle principal é por usuário, no banco)
// ----------------------------------------------------------------------------
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'TOO_MANY_REQUESTS', message: 'Muitas solicitações. Tente novamente mais tarde.' },
});

// ----------------------------------------------------------------------------
// Rota
// ----------------------------------------------------------------------------
const router = express.Router();

router.post('/resend', ipLimiter, authenticate, express.json({ limit: '1kb' }), async (req, res, next) => {
  try {
    const { userId, tenantId } = req.auth || {};
    if (!userId || !tenantId) {
      throw new HttpError(401, 'UNAUTHENTICATED', 'Não autenticado.');
    }

    // Validação estrita da entrada: apenas o canal, com lista fechada.
    const channel = req.body?.channel === 'sms' ? 'sms' : req.body?.channel === 'email' ? 'email' : null;
    if (!channel) {
      throw new HttpError(400, 'INVALID_CHANNEL', "Canal inválido. Use 'email' ou 'sms'.");
    }

    // ------------------------------------------------------------------------
    // Fase 1: transação — valida, aplica limites, invalida códigos antigos e
    // grava o novo. O envio ocorre DEPOIS do commit (não segura lock em I/O externo).
    // ------------------------------------------------------------------------
    const code = generateNumericCode();
    const codeHash = hashCode({ tenantId, userId, channel, code });
    const expiresAt = new Date(Date.now() + CODE_TTL_MS);

    let destination;
    let newCodeId;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Usuário + tenant, SEMPRE filtrando por tenant_id. FOR UPDATE serializa
      // requisições concorrentes do mesmo usuário (evita burlar o cooldown).
      const { rows: userRows } = await client.query(
        `SELECT u.email, u.phone, u.email_verified_at, u.phone_verified_at,
                t.subscription_status
           FROM users u
           JOIN tenants t ON t.id = u.tenant_id
          WHERE u.id = $1
            AND u.tenant_id = $2
          FOR UPDATE OF u`,
        [userId, tenantId]
      );

      const user = userRows[0];
      if (!user) {
        throw new HttpError(404, 'USER_NOT_FOUND', 'Usuário não encontrado.');
      }

      // Regra de negócio: tenant com assinatura inativa não dispara envios.
      if (user.subscription_status !== 'active') {
        throw new HttpError(403, 'SUBSCRIPTION_INACTIVE', 'A assinatura da empresa não está ativa.');
      }

      // O destino é o contato CADASTRADO — nunca algo vindo da requisição.
      destination = channel === 'email' ? user.email : user.phone;
      const alreadyVerified = channel === 'email' ? user.email_verified_at : user.phone_verified_at;

      if (!destination) {
        throw new HttpError(422, 'NO_CONTACT_ON_FILE', 'Não há contato cadastrado para este canal.');
      }
      if (alreadyVerified) {
        throw new HttpError(409, 'ALREADY_VERIFIED', 'Este contato já foi verificado.');
      }

      // Cooldown e limite por hora (ambos calculados no banco, relógio único).
      const { rows: statRows } = await client.query(
        `SELECT
            COUNT(*) FILTER (WHERE created_at > now() - interval '1 hour')::int AS sent_last_hour,
            MAX(created_at) AS last_sent_at,
            EXTRACT(EPOCH FROM (now() - MAX(created_at)))::int AS seconds_since_last
           FROM contact_verification_codes
          WHERE tenant_id = $1 AND user_id = $2 AND channel = $3`,
        [tenantId, userId, channel]
      );
      const stats = statRows[0];

      const cooldownSec = RESEND_COOLDOWN_MS / 1000;
      if (stats.last_sent_at && stats.seconds_since_last < cooldownSec) {
        const retryAfter = cooldownSec - stats.seconds_since_last;
        throw new HttpError(429, 'RESEND_COOLDOWN', 'Aguarde antes de solicitar um novo código.', { retryAfter });
      }
      if (stats.sent_last_hour >= MAX_SENDS_PER_HOUR) {
        throw new HttpError(429, 'HOURLY_LIMIT_REACHED', 'Limite de reenvios atingido. Tente novamente mais tarde.', {
          retryAfter: 3600,
        });
      }

      // Invalida códigos anteriores ainda pendentes.
      await client.query(
        `UPDATE contact_verification_codes
            SET invalidated_at = now()
          WHERE tenant_id = $1 AND user_id = $2 AND channel = $3
            AND consumed_at IS NULL AND invalidated_at IS NULL`,
        [tenantId, userId, channel]
      );

      // Grava o novo código (somente o hash).
      const { rows: insertRows } = await client.query(
        `INSERT INTO contact_verification_codes
                (tenant_id, user_id, channel, code_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id`,
        [tenantId, userId, channel, codeHash, expiresAt]
      );
      newCodeId = insertRows[0].id;

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }

    // ------------------------------------------------------------------------
    // Fase 2: envio ao destinatário cadastrado.
    // ------------------------------------------------------------------------
    const expiresInMinutes = CODE_TTL_MS / 60000;
    try {
      if (channel === 'email') {
        await notifier.sendEmail({ to: destination, code, expiresInMinutes });
      } else {
        await notifier.sendSms({ to: destination, code, expiresInMinutes });
      }
    } catch (sendErr) {
      // Falha no provedor: invalida o código para não deixar um código "órfão" válido.
      await pool
        .query(
          `UPDATE contact_verification_codes SET invalidated_at = now()
            WHERE id = $1 AND tenant_id = $2`,
          [newCodeId, tenantId]
        )
        .catch(() => {});

      // Log sem o código e sem o destino completo.
      console.error('[verification] falha no envio', {
        tenantId,
        userId,
        channel,
        codeId: newCodeId,
        error: sendErr.message,
      });
      throw new HttpError(502, 'DELIVERY_FAILED', 'Não foi possível enviar o código. Tente novamente.');
    }

    // Auditoria (sem dados sensíveis).
    console.info('[verification] código reenviado', { tenantId, userId, channel, codeId: newCodeId });

    // 202: o envio foi aceito/disparado. Nunca devolver o código na resposta.
    return res.status(202).json({
      message: 'Código de verificação enviado.',
      channel,
      destination: channel === 'email' ? maskEmail(destination) : maskPhone(destination),
      expiresInSeconds: CODE_TTL_MS / 1000,
      resendAvailableInSeconds: RESEND_COOLDOWN_MS / 1000,
    });
  } catch (err) {
    return next(err);
  }
});

// ----------------------------------------------------------------------------
// Tratamento de erros (use um handler global equivalente na sua aplicação)
// ----------------------------------------------------------------------------
router.use((err, req, res, _next) => {
  if (err instanceof HttpError) {
    if (err.extra.retryAfter) res.set('Retry-After', String(err.extra.retryAfter));
    return res.status(err.status).json({ error: err.code, message: err.message, ...err.extra });
  }
  console.error('[verification] erro inesperado', { error: err.message });
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Erro interno.' });
});

module.exports = router;

// Uso:
//   app.use('/api/v1/contact-verification', require('./routes/contact-verification'));