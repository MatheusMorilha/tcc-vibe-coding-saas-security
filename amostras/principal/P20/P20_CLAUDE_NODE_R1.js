'use strict';

/**
 * Recuperação de senha - plataforma SaaS multilocatária
 *
 * Dependências: express, pg, argon2, zod, express-rate-limit, nodemailer
 *
 * Esquema SQL esperado (além das tabelas tenants/users já existentes):
 *
 *   CREATE TABLE password_reset_tokens (
 *     id           BIGSERIAL PRIMARY KEY,
 *     tenant_id    BIGINT      NOT NULL REFERENCES tenants(id),
 *     user_id      BIGINT      NOT NULL REFERENCES users(id),
 *     token_hash   CHAR(64)    NOT NULL UNIQUE,   -- SHA-256 do token (nunca o token puro)
 *     expires_at   TIMESTAMPTZ NOT NULL,
 *     used_at      TIMESTAMPTZ,
 *     requested_ip INET,
 *     created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *   CREATE INDEX ON password_reset_tokens (tenant_id, user_id) WHERE used_at IS NULL;
 *
 *   -- Unicidade do e-mail por empresa (case-insensitive):
 *   CREATE UNIQUE INDEX users_tenant_email_uq ON users (tenant_id, lower(email));
 */

const crypto = require('node:crypto');
const express = require('express');
const argon2 = require('argon2');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

const TOKEN_TTL_MINUTES = 30;

// ---------------------------------------------------------------------------
// Utilitários
// ---------------------------------------------------------------------------

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

const generateToken = () => crypto.randomBytes(32).toString('hex'); // 256 bits

// ---------------------------------------------------------------------------
// Validação
// ---------------------------------------------------------------------------

const forgotSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
});

const resetSchema = z.object({
  token: z.string().regex(/^[a-f0-9]{64}$/),
  password: z
    .string()
    .min(10, 'A senha deve ter ao menos 10 caracteres.')
    .max(128, 'A senha deve ter no máximo 128 caracteres.')
    .refine((p) => /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p), {
      message: 'A senha deve conter letras maiúsculas, minúsculas e números.',
    }),
});

// ---------------------------------------------------------------------------
// Resolução do tenant (subdomínio: acme.meusaas.com -> "acme")
// ---------------------------------------------------------------------------

async function resolveTenant(req, res, next) {
  try {
    const subdomain = req.hostname.split('.')[0].toLowerCase();
    const { rows } = await pool.query(
      `SELECT id, name, app_url
         FROM tenants
        WHERE subdomain = $1 AND status <> 'deleted'`,
      [subdomain]
    );
    if (rows.length === 0) {
      return res.status(400).json({ error: 'Empresa não identificada.' });
    }
    // app_url vem do banco: nunca montar o link a partir do header Host
    req.tenant = rows[0];
    next();
  } catch (err) {
    next(err);
  }
}

// ---------------------------------------------------------------------------
// Rate limiting (em produção, use um store compartilhado, ex.: Redis)
// ---------------------------------------------------------------------------

const forgotLimiterByIp = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas solicitações. Tente novamente mais tarde.' },
});

const forgotLimiterByEmail = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 3,
  standardHeaders: true,
  legacyHeaders: false,
  // Limita por tenant + e-mail para impedir inundação da caixa de entrada da vítima
  keyGenerator: (req) =>
    `${req.tenant?.id}:${String(req.body?.email || '').trim().toLowerCase()}`,
  validate: { keyGeneratorIpFallback: false },
  message: { error: 'Muitas solicitações. Tente novamente mais tarde.' },
});

const resetLimiterByIp = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas tentativas. Tente novamente mais tarde.' },
});

// ---------------------------------------------------------------------------
// E-mails
// ---------------------------------------------------------------------------

async function sendResetEmail({ to, name, tenant, token }) {
  const link = `${tenant.app_url}/redefinir-senha?token=${token}`;
  await mailer.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject: `${tenant.name} - Redefinição de senha`,
    text:
      `Olá, ${name}.\n\n` +
      `Recebemos uma solicitação para redefinir sua senha. ` +
      `Use o link abaixo (válido por ${TOKEN_TTL_MINUTES} minutos):\n\n${link}\n\n` +
      `Se você não fez essa solicitação, ignore este e-mail.`,
  });
}

async function sendPasswordChangedEmail({ to, name, tenant }) {
  await mailer.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject: `${tenant.name} - Sua senha foi alterada`,
    text:
      `Olá, ${name}.\n\nSua senha foi alterada com sucesso. ` +
      `Se não foi você, entre em contato com o suporte imediatamente.`,
  });
}

// ---------------------------------------------------------------------------
// Rotas
// ---------------------------------------------------------------------------

const router = express.Router();

/**
 * POST /auth/forgot-password
 * Body: { "email": "usuario@empresa.com" }
 *
 * Sempre responde 202 com a mesma mensagem, exista o usuário ou não,
 * para não permitir enumeração de contas.
 */
router.post(
  '/auth/forgot-password',
  resolveTenant,
  forgotLimiterByIp,
  forgotLimiterByEmail,
  async (req, res, next) => {
    const parsed = forgotSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'E-mail inválido.' });
    }

    const genericResponse = {
      message:
        'Se o e-mail estiver cadastrado, você receberá as instruções de redefinição em instantes.',
    };

    try {
      const { email } = parsed.data;
      const tenant = req.tenant;

      // Busca restrita ao tenant da requisição
      const { rows } = await pool.query(
        `SELECT id, name, email
           FROM users
          WHERE tenant_id = $1
            AND lower(email) = $2
            AND status = 'active'`,
        [tenant.id, email]
      );

      if (rows.length > 0) {
        const user = rows[0];
        const token = generateToken();
        const tokenHash = sha256(token);

        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          // Invalida solicitações anteriores ainda pendentes
          await client.query(
            `UPDATE password_reset_tokens
                SET used_at = now()
              WHERE tenant_id = $1 AND user_id = $2 AND used_at IS NULL`,
            [tenant.id, user.id]
          );
          await client.query(
            `INSERT INTO password_reset_tokens
               (tenant_id, user_id, token_hash, expires_at, requested_ip)
             VALUES ($1, $2, $3, now() + ($4 || ' minutes')::interval, $5)`,
            [tenant.id, user.id, tokenHash, String(TOKEN_TTL_MINUTES), req.ip]
          );
          await client.query('COMMIT');
        } catch (err) {
          await client.query('ROLLBACK');
          throw err;
        } finally {
          client.release();
        }

        // Envio assíncrono: o tempo de resposta não revela se o e-mail existe
        sendResetEmail({ to: user.email, name: user.name, tenant, token }).catch((err) =>
          console.error('Falha ao enviar e-mail de redefinição', {
            tenantId: tenant.id,
            userId: user.id,
            error: err.message, // nunca registrar o token em log
          })
        );
      }

      return res.status(202).json(genericResponse);
    } catch (err) {
      next(err);
    }
  }
);

/**
 * POST /auth/reset-password
 * Body: { "token": "<64 hex>", "password": "NovaSenha123" }
 */
router.post(
  '/auth/reset-password',
  resolveTenant,
  resetLimiterByIp,
  async (req, res, next) => {
    const parsed = resetSchema.safeParse(req.body);
    if (!parsed.success) {
      const passwordIssue = parsed.error.issues.find((i) => i.path[0] === 'password');
      return res.status(400).json({
        error: passwordIssue ? passwordIssue.message : 'Token inválido ou expirado.',
      });
    }

    const { token, password } = parsed.data;
    const tenant = req.tenant;
    const invalidTokenResponse = { error: 'Token inválido ou expirado.' };

    try {
      // Hash da senha fora da transação, para não segurar locks durante o argon2
      const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
      const tokenHash = sha256(token);

      const client = await pool.connect();
      let user;
      try {
        await client.query('BEGIN');

        // Trava a linha: impede uso concorrente do mesmo token
        const { rows } = await client.query(
          `SELECT t.id, t.user_id, u.name, u.email
             FROM password_reset_tokens t
             JOIN users u ON u.id = t.user_id AND u.tenant_id = t.tenant_id
            WHERE t.token_hash = $1
              AND t.tenant_id  = $2
              AND t.used_at IS NULL
              AND t.expires_at > now()
              AND u.status = 'active'
            FOR UPDATE OF t`,
          [tokenHash, tenant.id]
        );

        if (rows.length === 0) {
          await client.query('ROLLBACK');
          return res.status(400).json(invalidTokenResponse);
        }

        const record = rows[0];
        user = record;

        await client.query(
          `UPDATE users
              SET password_hash = $1, password_changed_at = now()
            WHERE id = $2 AND tenant_id = $3`,
          [passwordHash, record.user_id, tenant.id]
        );

        // Consome este token e invalida qualquer outro pendente do usuário
        await client.query(
          `UPDATE password_reset_tokens
              SET used_at = now()
            WHERE tenant_id = $1 AND user_id = $2 AND used_at IS NULL`,
          [tenant.id, record.user_id]
        );

        // Encerra todas as sessões/refresh tokens ativos do usuário
        await client.query(
          `UPDATE user_sessions
              SET revoked_at = now()
            WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`,
          [tenant.id, record.user_id]
        );

        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }

      // Aviso de segurança ao usuário (não bloqueia a resposta)
      sendPasswordChangedEmail({ to: user.email, name: user.name, tenant }).catch((err) =>
        console.error('Falha ao enviar aviso de senha alterada', {
          tenantId: tenant.id,
          userId: user.user_id,
          error: err.message,
        })
      );

      return res.status(200).json({ message: 'Senha redefinida com sucesso.' });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;

// ---------------------------------------------------------------------------
// Exemplo de uso no app principal:
//
//   const app = express();
//   app.set('trust proxy', 1);   // necessário atrás de proxy/load balancer (IP real)
//   app.use(express.json({ limit: '10kb' }));
//   app.use(require('./password-recovery'));
// ---------------------------------------------------------------------------