// password-recovery.routes.js
// Dependências: express, express-rate-limit, pg, argon2, nodemailer, zod
//
// Esquema esperado (PostgreSQL):
//
//   CREATE TABLE password_reset_tokens (
//     id           BIGSERIAL PRIMARY KEY,
//     tenant_id    BIGINT      NOT NULL REFERENCES tenants(id),
//     user_id      BIGINT      NOT NULL REFERENCES users(id),
//     token_hash   CHAR(64)    NOT NULL UNIQUE,   -- SHA-256 do token (nunca o token puro)
//     expires_at   TIMESTAMPTZ NOT NULL,
//     used_at      TIMESTAMPTZ,
//     requested_ip INET,
//     created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
//   );
//   CREATE INDEX ON password_reset_tokens (tenant_id, user_id, created_at);
//
//   -- users: (tenant_id, lower(email)) deve ser UNIQUE, pois o mesmo e-mail
//   -- pode existir em empresas diferentes na mesma base.

import crypto from 'node:crypto';
import express from 'express';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import pg from 'pg';
import argon2 from 'argon2';
import nodemailer from 'nodemailer';
import { z } from 'zod';

const {
  DATABASE_URL,
  APP_DOMAIN,            // ex.: "meusaas.com.br" (tenants em {slug}.meusaas.com.br)
  SMTP_URL,
  MAIL_FROM = 'no-reply@meusaas.com.br',
} = process.env;

const TOKEN_TTL_MINUTES = 30;
const MAX_REQUESTS_PER_USER_PER_HOUR = 3;

const pool = new pg.Pool({ connectionString: DATABASE_URL });
const mailer = nodemailer.createTransport(SMTP_URL);

/* ------------------------------------------------------------------ */
/* Utilitários                                                         */
/* ------------------------------------------------------------------ */

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

// Token com 256 bits de entropia, URL-safe. Só o hash vai para o banco.
const generateToken = () => crypto.randomBytes(32).toString('hex'); // 64 chars hex

async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

const noStore = (_req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
};

/* ------------------------------------------------------------------ */
/* Resolução do tenant (isolamento multilocatário)                     */
/* ------------------------------------------------------------------ */
// O tenant vem do subdomínio (Host), nunca do corpo da requisição.
// Se você usa outro mecanismo (header interno do gateway, JWT, etc.),
// basta substituir este middleware: o restante só depende de req.tenant.

async function resolveTenant(req, res, next) {
  try {
    const host = req.hostname.toLowerCase();
    if (!host.endsWith(`.${APP_DOMAIN}`)) {
      return res.status(404).json({ error: 'Recurso não encontrado.' });
    }
    const slug = host.slice(0, -(APP_DOMAIN.length + 1));

    const { rows } = await pool.query(
      `SELECT id, slug, name FROM tenants WHERE slug = $1 AND deleted_at IS NULL`,
      [slug],
    );
    if (!rows[0]) return res.status(404).json({ error: 'Recurso não encontrado.' });

    req.tenant = rows[0];
    next();
  } catch (err) {
    next(err);
  }
}

/* ------------------------------------------------------------------ */
/* Rate limiting                                                       */
/* ------------------------------------------------------------------ */

const forgotLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.tenant?.id}:${ipKeyGenerator(req.ip)}`,
  message: { error: 'Muitas tentativas. Tente novamente mais tarde.' },
});

const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.tenant?.id}:${ipKeyGenerator(req.ip)}`,
  message: { error: 'Muitas tentativas. Tente novamente mais tarde.' },
});

/* ------------------------------------------------------------------ */
/* Validação                                                           */
/* ------------------------------------------------------------------ */

const forgotSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
});

const resetSchema = z.object({
  token: z.string().regex(/^[0-9a-f]{64}$/i),
  newPassword: z
    .string()
    .min(12, 'A senha deve ter ao menos 12 caracteres.')
    .max(128, 'A senha deve ter no máximo 128 caracteres.')
    .refine((p) => /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p), {
      message: 'A senha deve conter letras maiúsculas, minúsculas e números.',
    }),
});

/* ------------------------------------------------------------------ */
/* E-mails                                                             */
/* ------------------------------------------------------------------ */

function sendResetEmail({ to, tenant, token }) {
  // Link montado a partir de configuração confiável (nunca do header Host recebido).
  // O token vai no fragmento (#), que não é enviado ao servidor nem vaza em logs/Referer.
  const link = `https://${tenant.slug}.${APP_DOMAIN}/redefinir-senha#token=${token}`;

  return mailer.sendMail({
    from: MAIL_FROM,
    to,
    subject: `Redefinição de senha - ${tenant.name}`,
    text:
      `Recebemos uma solicitação para redefinir sua senha.\n\n` +
      `Acesse o link abaixo (válido por ${TOKEN_TTL_MINUTES} minutos):\n${link}\n\n` +
      `Se você não fez essa solicitação, ignore este e-mail.`,
  });
}

function sendPasswordChangedEmail({ to, tenant }) {
  return mailer.sendMail({
    from: MAIL_FROM,
    to,
    subject: `Sua senha foi alterada - ${tenant.name}`,
    text:
      `A senha da sua conta foi alterada com sucesso.\n` +
      `Se não foi você, entre em contato com o suporte imediatamente.`,
  });
}

/* ------------------------------------------------------------------ */
/* Rotas                                                               */
/* ------------------------------------------------------------------ */

const router = express.Router();
router.use(noStore, resolveTenant);

// Resposta idêntica exista o e-mail ou não (evita enumeração de usuários).
const GENERIC_FORGOT_RESPONSE = {
  message:
    'Se o e-mail estiver cadastrado, você receberá as instruções de redefinição em instantes.',
};

/**
 * POST /auth/forgot-password
 * body: { "email": "usuario@empresa.com" }
 */
router.post('/auth/forgot-password', forgotLimiter, async (req, res, next) => {
  try {
    const parsed = forgotSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'E-mail inválido.' });
    }
    const { email } = parsed.data;
    const tenant = req.tenant;

    const issued = await withTransaction(async (db) => {
      // Escopo SEMPRE por tenant_id: o mesmo e-mail pode existir em outra empresa.
      const { rows } = await db.query(
        `SELECT id, email
           FROM users
          WHERE tenant_id = $1
            AND lower(email) = $2
            AND status = 'active'
          FOR UPDATE`, // serializa solicitações concorrentes do mesmo usuário
        [tenant.id, email],
      );
      const user = rows[0];
      if (!user) return null;

      // Limite por usuário: evita spam de e-mails na caixa da vítima.
      const { rows: recent } = await db.query(
        `SELECT count(*)::int AS n
           FROM password_reset_tokens
          WHERE tenant_id = $1 AND user_id = $2
            AND created_at > now() - interval '1 hour'`,
        [tenant.id, user.id],
      );
      if (recent[0].n >= MAX_REQUESTS_PER_USER_PER_HOUR) return null;

      // Invalida tokens pendentes anteriores: só o mais recente é válido.
      await db.query(
        `UPDATE password_reset_tokens
            SET used_at = now()
          WHERE tenant_id = $1 AND user_id = $2 AND used_at IS NULL`,
        [tenant.id, user.id],
      );

      const token = generateToken();
      await db.query(
        `INSERT INTO password_reset_tokens
           (tenant_id, user_id, token_hash, expires_at, requested_ip)
         VALUES ($1, $2, $3, now() + make_interval(mins => $4), $5)`,
        [tenant.id, user.id, sha256(token), TOKEN_TTL_MINUTES, req.ip],
      );

      return { to: user.email, token };
    });

    // Envio fora do caminho da resposta: o tempo de resposta não revela
    // se o e-mail existe. Em produção, prefira uma fila (BullMQ, SQS...).
    if (issued) {
      sendResetEmail({ to: issued.to, tenant, token: issued.token }).catch((err) =>
        console.error('[forgot-password] falha ao enviar e-mail', {
          tenantId: tenant.id,
          error: err.message, // nunca logar o token
        }),
      );
    }

    return res.status(202).json(GENERIC_FORGOT_RESPONSE);
  } catch (err) {
    next(err);
  }
});

/**
 * POST /auth/reset-password
 * body: { "token": "<64 hex>", "newPassword": "..." }
 */
router.post('/auth/reset-password', resetLimiter, async (req, res, next) => {
  try {
    const parsed = resetSchema.safeParse(req.body);
    if (!parsed.success) {
      const isPasswordIssue = parsed.error.issues.some((i) => i.path[0] === 'newPassword');
      return res.status(400).json({
        error: isPasswordIssue
          ? parsed.error.issues.find((i) => i.path[0] === 'newPassword').message
          : 'Token inválido ou expirado.',
      });
    }
    const { token, newPassword } = parsed.data;
    const tenant = req.tenant;

    // Hash da senha fora da transação para não segurar locks durante o custo do argon2.
    const passwordHash = await argon2.hash(newPassword, { type: argon2.argon2id });

    const result = await withTransaction(async (db) => {
      // Consumo atômico: trava a linha do token; duas requisições simultâneas
      // com o mesmo token não conseguem ambas ter sucesso.
      const { rows } = await db.query(
        `SELECT id, user_id
           FROM password_reset_tokens
          WHERE token_hash = $1
            AND tenant_id  = $2          -- token de outra empresa não vale aqui
            AND used_at IS NULL
            AND expires_at > now()
          FOR UPDATE`,
        [sha256(token.toLowerCase()), tenant.id],
      );
      const record = rows[0];
      if (!record) return null;

      const { rows: updated } = await db.query(
        `UPDATE users
            SET password_hash = $1,
                password_changed_at = now(),
                failed_login_attempts = 0,
                locked_until = NULL
          WHERE id = $2 AND tenant_id = $3 AND status = 'active'
        RETURNING email`,
        [passwordHash, record.user_id, tenant.id],
      );
      if (!updated[0]) return null;

      // Consome este token e invalida qualquer outro pendente do usuário.
      await db.query(
        `UPDATE password_reset_tokens
            SET used_at = now()
          WHERE tenant_id = $1 AND user_id = $2 AND used_at IS NULL`,
        [tenant.id, record.user_id],
      );

      // Encerra sessões/refresh tokens existentes (quem tinha acesso indevido perde-o).
      await db.query(
        `UPDATE refresh_tokens
            SET revoked_at = now()
          WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`,
        [tenant.id, record.user_id],
      );

      return { email: updated[0].email };
    });

    // Mensagem única para token inexistente, expirado, usado ou de outro tenant.
    if (!result) {
      return res.status(400).json({ error: 'Token inválido ou expirado.' });
    }

    sendPasswordChangedEmail({ to: result.email, tenant }).catch((err) =>
      console.error('[reset-password] falha ao enviar aviso', {
        tenantId: tenant.id,
        error: err.message,
      }),
    );

    return res.status(200).json({ message: 'Senha redefinida com sucesso.' });
  } catch (err) {
    next(err);
  }
});

export default router;

/* ------------------------------------------------------------------ */
/* Exemplo de uso no app                                               */
/* ------------------------------------------------------------------ */
// import passwordRecoveryRouter from './password-recovery.routes.js';
//
// const app = express();
// app.set('trust proxy', 1);            // necessário para req.ip correto atrás de proxy/LB
// app.use(express.json({ limit: '10kb' }));
// app.use(passwordRecoveryRouter);
//
// app.use((err, _req, res, _next) => {  // handler global: não vaza detalhes internos
//   console.error(err);
//   res.status(500).json({ error: 'Erro interno.' });
// });