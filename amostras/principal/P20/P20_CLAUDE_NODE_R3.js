/**
 * password-recovery.routes.js
 *
 * Rotas:
 *   POST /auth/forgot-password  { email }                -> dispara e-mail de redefinição
 *   POST /auth/reset-password   { token, password }      -> conclui a alteração
 *
 * Dependências: express, pg, bcrypt, zod, express-rate-limit
 *
 * Esquema SQL esperado (PostgreSQL):
 *
 *   -- users: e-mail é único POR EMPRESA, não globalmente
 *   -- UNIQUE (tenant_id, lower(email))
 *   -- colunas usadas: id, tenant_id, email, name, password_hash, is_active, token_version
 *
 *   CREATE TABLE password_reset_tokens (
 *     id          BIGSERIAL PRIMARY KEY,
 *     tenant_id   UUID        NOT NULL,
 *     user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 *     token_hash  CHAR(64)    NOT NULL UNIQUE,   -- SHA-256 do token (nunca o token em claro)
 *     expires_at  TIMESTAMPTZ NOT NULL,
 *     used_at     TIMESTAMPTZ,
 *     created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *   CREATE INDEX ON password_reset_tokens (user_id) WHERE used_at IS NULL;
 */

'use strict';

const crypto = require('node:crypto');
const express = require('express');
const bcrypt = require('bcrypt');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');

const TOKEN_TTL_MINUTES = 30;
const BCRYPT_ROUNDS = 12;

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

/** Mesma resposta sempre, exista o e-mail ou não (evita enumeração de usuários). */
const GENERIC_FORGOT_RESPONSE = {
  message:
    'Se o e-mail informado estiver cadastrado, enviaremos as instruções de redefinição de senha.',
};

const forgotSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
});

const resetSchema = z.object({
  token: z.string().regex(/^[a-f0-9]{64}$/i, 'Token inválido'),
  password: z
    .string()
    .min(10, 'A senha deve ter ao menos 10 caracteres')
    .max(128, 'A senha deve ter no máximo 128 caracteres')
    .regex(/[a-z]/, 'Inclua ao menos uma letra minúscula')
    .regex(/[A-Z]/, 'Inclua ao menos uma letra maiúscula')
    .regex(/[0-9]/, 'Inclua ao menos um número'),
});

/**
 * @param {object} deps
 * @param {import('pg').Pool} deps.db
 * @param {(msg: {to: string, name: string, resetUrl: string, expiresInMinutes: number}) => Promise<void>} deps.sendResetEmail
 * @param {(tenantId: string) => Promise<string>} deps.getTenantBaseUrl  URL do front DO TENANT, vinda de config/banco (nunca do header Host)
 * @param {{error: Function, warn: Function, info: Function}} deps.logger
 */
function createPasswordRecoveryRouter({ db, sendResetEmail, getTenantBaseUrl, logger }) {
  const router = express.Router();

  // Rate limit por IP + por e-mail/tenant, para barrar abuso e e-mail bombing.
  const forgotLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) =>
      `${req.tenantId}:${String(req.body?.email || '').toLowerCase()}:${req.ip}`,
    handler: (_req, res) => res.status(429).json({ message: 'Muitas tentativas. Tente novamente mais tarde.' }),
  });

  const resetLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) => res.status(429).json({ message: 'Muitas tentativas. Tente novamente mais tarde.' }),
  });

  /**
   * POST /auth/forgot-password
   * Requer que um middleware anterior resolva o tenant (subdomínio, domínio
   * customizado etc.) e defina req.tenantId. O tenant NUNCA vem do corpo da
   * requisição confiando no cliente sem validação.
   */
  router.post('/forgot-password', forgotLimiter, async (req, res) => {
    const parsed = forgotSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ message: 'E-mail inválido.' });
    }
    if (!req.tenantId) {
      return res.status(400).json({ message: 'Empresa não identificada.' });
    }

    const { email } = parsed.data;
    const tenantId = req.tenantId;

    // Responde imediatamente com resposta idêntica; o trabalho real roda depois,
    // assim o tempo de resposta não revela se o e-mail existe.
    res.status(202).json(GENERIC_FORGOT_RESPONSE);

    setImmediate(async () => {
      try {
        // Escopo SEMPRE por tenant_id: o mesmo e-mail pode existir em outras empresas.
        const { rows } = await db.query(
          `SELECT id, name, email
             FROM users
            WHERE tenant_id = $1
              AND lower(email) = $2
              AND is_active = true
            LIMIT 1`,
          [tenantId, email],
        );
        const user = rows[0];
        if (!user) return;

        // Token aleatório de 256 bits; só o hash é persistido.
        const token = crypto.randomBytes(32).toString('hex');
        const tokenHash = sha256(token);

        const client = await db.connect();
        try {
          await client.query('BEGIN');

          // Invalida solicitações anteriores pendentes deste usuário.
          await client.query(
            `UPDATE password_reset_tokens
                SET used_at = now()
              WHERE user_id = $1 AND tenant_id = $2 AND used_at IS NULL`,
            [user.id, tenantId],
          );

          await client.query(
            `INSERT INTO password_reset_tokens (tenant_id, user_id, token_hash, expires_at)
             VALUES ($1, $2, $3, now() + make_interval(mins => $4))`,
            [tenantId, user.id, tokenHash, TOKEN_TTL_MINUTES],
          );

          await client.query('COMMIT');
        } catch (err) {
          await client.query('ROLLBACK');
          throw err;
        } finally {
          client.release();
        }

        const baseUrl = await getTenantBaseUrl(tenantId);
        // Token no fragmento (#) não vai para logs de servidor nem header Referer.
        const resetUrl = `${baseUrl}/redefinir-senha#token=${token}`;

        await sendResetEmail({
          to: user.email,
          name: user.name,
          resetUrl,
          expiresInMinutes: TOKEN_TTL_MINUTES,
        });
      } catch (err) {
        // Nunca logar o token nem o e-mail em claro.
        logger.error({ err: err.message, tenantId }, 'Falha ao processar forgot-password');
      }
    });
  });

  /**
   * POST /auth/reset-password
   * O token já identifica usuário e tenant; o tenant do request, se presente,
   * é conferido para impedir uso do token em outro contexto.
   */
  router.post('/reset-password', resetLimiter, async (req, res) => {
    const parsed = resetSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        message: 'Dados inválidos.',
        errors: parsed.error.issues.map((i) => i.message),
      });
    }

    const { token, password } = parsed.data;
    const tokenHash = sha256(token.toLowerCase());

    // Hash da senha fora da transação para não segurar conexão durante o custo do bcrypt.
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const client = await db.connect();
    try {
      await client.query('BEGIN');

      // Consumo atômico: só um request consegue "queimar" o token (single-use, sem race condition).
      const consumed = await client.query(
        `UPDATE password_reset_tokens
            SET used_at = now()
          WHERE token_hash = $1
            AND used_at IS NULL
            AND expires_at > now()
        RETURNING user_id, tenant_id`,
        [tokenHash],
      );

      const record = consumed.rows[0];
      if (!record || (req.tenantId && record.tenant_id !== req.tenantId)) {
        await client.query('ROLLBACK');
        return res.status(400).json({ message: 'Token inválido ou expirado.' });
      }

      // Atualiza a senha com escopo de tenant e incrementa token_version
      // para invalidar sessões/JWTs/refresh tokens já emitidos.
      const updated = await client.query(
        `UPDATE users
            SET password_hash = $1,
                token_version = token_version + 1,
                updated_at = now()
          WHERE id = $2 AND tenant_id = $3 AND is_active = true`,
        [passwordHash, record.user_id, record.tenant_id],
      );

      if (updated.rowCount !== 1) {
        await client.query('ROLLBACK');
        return res.status(400).json({ message: 'Token inválido ou expirado.' });
      }

      // Invalida quaisquer outros tokens de redefinição pendentes do usuário.
      await client.query(
        `UPDATE password_reset_tokens
            SET used_at = now()
          WHERE user_id = $1 AND tenant_id = $2 AND used_at IS NULL`,
        [record.user_id, record.tenant_id],
      );

      // Se houver tabela de refresh tokens/sessões, revogue-as aqui:
      // await client.query('DELETE FROM sessions WHERE user_id = $1 AND tenant_id = $2', [...]);

      await client.query('COMMIT');

      return res.status(200).json({ message: 'Senha redefinida com sucesso.' });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      logger.error({ err: err.message }, 'Falha ao processar reset-password');
      return res.status(500).json({ message: 'Erro interno. Tente novamente.' });
    } finally {
      client.release();
    }
  });

  return router;
}

module.exports = { createPasswordRecoveryRouter };

/* ------------------------------------------------------------------
 * Exemplo de montagem (app.js)
 * ------------------------------------------------------------------
 *
 * const app = express();
 * app.set('trust proxy', 1);          // necessário para req.ip correto atrás de proxy
 * app.use(express.json({ limit: '10kb' }));
 *
 * // Resolve o tenant pelo subdomínio (ex.: acme.suaplataforma.com)
 * app.use(async (req, _res, next) => {
 *   const slug = req.hostname.split('.')[0];
 *   const { rows } = await db.query(
 *     `SELECT id FROM tenants WHERE slug = $1 AND status <> 'deleted'`, [slug]);
 *   req.tenantId = rows[0]?.id;
 *   next();
 * });
 *
 * app.use('/auth', createPasswordRecoveryRouter({ db, sendResetEmail, getTenantBaseUrl, logger }));
 */