const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// -----------------------------------------------------------------------------
// Dependências esperadas
// -----------------------------------------------------------------------------
// db.query(sql, params)
// emailService.send({ to, subject, text })
//
// Exemplo de estrutura de usuário:
//
// users
//   id
//   tenant_id
//   email
//   password_hash
//   reset_token_hash
//   reset_token_expires_at
//
// O hash da senha deve ser produzido por Argon2id ou bcrypt.
// -----------------------------------------------------------------------------

const db = require("./db");
const emailService = require("./emailService");

const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;

// -----------------------------------------------------------------------------
// Utilitários
// -----------------------------------------------------------------------------

function normalizeEmail(email) {
  return String(email|| "").trim().toLowerCase();
}

function generateResetToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

// Comparação segura para tokens já armazenados como hash.
function tokensEqual(receivedToken, storedHash) {
  if (!storedHash)return false;

  const receivedHash = hashToken(receivedToken);

  const receivedBuffer = Buffer.from(receivedHash, "hex");
  const storedBuffer = Buffer.from(storedHash, "hex");

  if (receivedBuffer.length !== storedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(receivedBuffer, storedBuffer);
}

// -----------------------------------------------------------------------------
// POST /api/auth/forgot-password
//
// Recebe o e-mail e envia o link de redefinição.
// -----------------------------------------------------------------------------

app.post("/api/auth/forgot-password", async (req, res)=> {
  try {
    const email = normalizeEmail(req.body.email);

    if (!email) {
      return res.status(400).json({
        message: "Informe um e-mail válido."
      });
    }

    // Não retornar 404 caso o usuário não exista.
    // Isso evita enumeração de contas.
    const result = await db.query(
      `
        SELECT id, tenant_id, email
        FROM users
        WHERE LOWER(email) = $1
        LIMIT 1
      `,
      [email]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(202).json({
        message:
          "Se existir uma conta associada a este e-mail, as instruções de recuperação serão enviadas."
      });
    }

    const rawToken = generateResetToken();
    const tokenHash = hashToken(rawToken);

    const expiresAt = new Date(
      Date.now()+ RESET_TOKEN_TTL_MS
    );

    // O token puro NÃO é armazenado no banco.
    await db.query(
      `
        UPDATE users
        SET
          reset_token_hash = $1,
          reset_token_expires_at = $2
        WHERE id = $3
          AND tenant_id = $4
      `,
      [
        tokenHash,
        expiresAt,
        user.id,
        user.tenant_id
      ]
    );

    const resetUrl =
      `${process.env.FRONTEND_URL}/reset-password` +
      `?token=${encodeURIComponent(rawToken)}`;

    await emailService.send({
      to: user.email,
      subject: "Redefinição de senha",
      text:
        `Solicitamos a redefinição da sua senha.\n\n` +
        `Acesse o link abaixo para criar uma nova senha:\n\n` +
        `${resetUrl}\n\n` +
        `Este link expira em 15 minutos.\n\n` +
        `Se você não solicitou esta alteração, ignore este e-mail.`
    });

    return res.status(202).json({
      message:
        "Se existir uma conta associada a este e-mail, as instruções de recuperação serão enviadas."
    });
  }catch (error) {
    console.error("forgot-password error:", error);

    return res.status(500).json({
      message: "Não foi possível processar a solicitação."
    });
  }
});

// -----------------------------------------------------------------------------
// POST /api/auth/reset-password
//
// Recebe o token e a nova senha.
// -----------------------------------------------------------------------------

app.post("/api/auth/reset-password", async (req, res)=> {
  try {
    const {token, newPassword }= req.body;

    if (
      typeof token!== "string" ||
      typeof newPassword!== "string"
    ) {
      return res.status(400).json({
        message: "Token e nova senha são obrigatórios."
      });
    }

    if (newPassword.length < 12) {
      return res.status(400).json({
        message: "A senha deve possuir pelo menos 12 caracteres."
      });
    }

    // Busca possíveis tokens válidos pelo hash.
    // O token recebido nunca é armazenado em texto puro.
    const tokenHash = hashToken(token);

    const result = await db.query(
      `
        SELECT
          id,
          tenant_id,
          email
        FROM users
        WHERE reset_token_hash = $1
          AND reset_token_expires_at > NOW()
        LIMIT 1
      `,
      [tokenHash]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({
        message: "Token inválido ou expirado."
      });
    }

    // A senha deve ser armazenada usando um algoritmo apropriado.
    // Aqui usamos bcrypt como exemplo.
    const bcrypt = require("bcrypt");

    const passwordHash = await bcrypt.hash(
      newPassword,
      12
    );

    /*
     * IMPORTANTE:
     * O tenant_id participa da atualização.
     *
     * Assim, mesmo sendo uma base compartilhada entre empresas,
     * a alteração permanece vinculada ao tenant correto.
     */
    await db.query(
      `
        UPDATE users
        SET
          password_hash = $1,
          reset_token_hash = NULL,
          reset_token_expires_at = NULL
        WHERE id = $2
          AND tenant_id = $3
          AND reset_token_hash = $4
      `,
      [
        passwordHash,
        user.id,
        user.tenant_id,
        tokenHash
      ]
    );

    /*
     * O token é invalidado imediatamente após o uso.
     * Portanto, ele funciona como token de uso único.
     */
    return res.status(200).json({
      message: "Senha alterada com sucesso."
    });
  }catch (error) {
    console.error("reset-password error:", error);

    return res.status(500).json({
      message: "Não foi possível alterar a senha."
    });
  }
});

// -----------------------------------------------------------------------------
// Inicialização
// -----------------------------------------------------------------------------

app.listen(process.env.PORT || 3000, ()=> {
  console.log("API iniciada.");
});