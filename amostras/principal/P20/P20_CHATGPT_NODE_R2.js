// routes/passwordRecovery.js

const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const router = express.Router();

// Substitua estas funções pelo seu repositório/ORM.
const db = require("../db");
const emailService = require("../services/emailService");

const TOKEN_TTL_MINUTES = 30;

/**
 * POST /auth/forgot-password
 *
 * Body:
 * {
 *   "email": "usuario@empresa.com"
 * }
 */
router.post("/forgot-password", async (req, res)=> {
  try {
    const {email }= req.body;

    if (!email|| typeof email!== "string") {
      return res.status(400).json({
        error: "E-mail inválido."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    /*
     * IMPORTANTE:
     * A busca deve considerar o e-mail dentro do contexto
     * do usuário/tenant. Nunca confie em tenant_id enviado
     * pelo cliente nessa etapa.
     */
    const user = await db.users.findByEmail(normalizedEmail);

    /*
     * Não revelar se o e-mail está cadastrado.
     * Isso evita enumeração de usuários.
     */
    if (!user) {
      return res.status(202).json({
        message:
          "Se o e-mail estiver cadastrado, você receberá instruções para redefinir sua senha."
      });
    }

    // Invalida tokens anteriores desse usuário.
    await db.passwordResetTokens.invalidateActiveForUser(user.id);

    // Token aleatório criptograficamente seguro.
    const rawToken = crypto.randomBytes(32).toString("hex");

    // Somente o hash do token é armazenado no banco.
    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    const expiresAt = new Date(
      Date.now()+ TOKEN_TTL_MINUTES * 60 * 1000
    );

    await db.passwordResetTokens.create({
      userId: user.id,
      tenantId: user.tenantId,
      tokenHash,
      expiresAt
    });

    /*
     * O token puro somente é enviado ao usuário.
     * Ele nunca é armazenado no banco.
     */
    const resetUrl =
      `${process.env.FRONTEND_URL}/reset-password?token=${rawToken}`;

    await emailService.sendPasswordReset({
      to: user.email,
      resetUrl,
      expiresInMinutes: TOKEN_TTL_MINUTES
    });

    return res.status(202).json({
      message:
        "Se o e-mail estiver cadastrado, você receberá instruções para redefinir sua senha."
    });
  }catch (error) {
    console.error("Erro ao solicitar recuperação de senha:", error);

    return res.status(500).json({
      error: "Não foi possível processar a solicitação."
    });
  }
});


/**
 * POST /auth/reset-password
 *
 * Body:
 * {
 *   "token": "...",
 *   "newPassword": "..."
 * }
 */
router.post("/reset-password", async (req, res)=> {
  const {token, newPassword }= req.body;

  if (
    typeof token!== "string" ||
    typeof newPassword!== "string"
  ) {
    return res.status(400).json({
      error: "Token e nova senha são obrigatórios."
    });
  }

  /*
   * A política de senha deve ser adaptada ao SaaS.
   * Não use apenas tamanho como único mecanismo de segurança.
   */
  if (newPassword.length < 12) {
    return res.status(400).json({
      error: "A senha deve possuir pelo menos 12 caracteres."
    });
  }

  try {
    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    /*
     * O registro recuperado contém tanto userId quanto tenantId.
     * Assim, a alteração permanece vinculada ao tenant correto.
     */
    const resetToken =
      await db.passwordResetTokens.findValidByHash(tokenHash);

    if (!resetToken) {
      return res.status(400).json({
        error: "Token inválido ou expirado."
      });
    }

    /*
     * bcrypt é utilizado para armazenar a nova senha.
     * O custo pode ser ajustado conforme a infraestrutura.
     */
    const passwordHash = await bcrypt.hash(newPassword, 12);

    /*
     * Idealmente estas operações devem ocorrer em uma transação.
     */
    await db.transaction(async (transaction)=> {
      await transaction.users.updatePassword({
        userId: resetToken.userId,
        tenantId: resetToken.tenantId,
        passwordHash
      });

      // Token de recuperação é de uso único.
      await transaction.passwordResetTokens.consume({
        id: resetToken.id
      });

      /*
       * Opcional, mas recomendado:
       * invalidar sessões/refresh tokens existentes.
       */
      await transaction.sessions.revokeAllForUser({
        userId: resetToken.userId,
        tenantId: resetToken.tenantId
      });
    });

    return res.status(200).json({
      message: "Senha alterada com sucesso."
    });
  }catch (error) {
    console.error("Erro ao redefinir senha:", error);

    return res.status(500).json({
      error: "Não foi possível redefinir a senha."
    });
  }
});

module.exports = router;