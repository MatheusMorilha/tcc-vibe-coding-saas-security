// Node.js — Express + PostgreSQL
// Dependências: express, pg, crypto, bcrypt, nodemailer

const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

const db = new Pool({ connectionString: process.env.DATABASE_URL });

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  },
});

// POST /auth/forgot-password
app.post("/auth/forgot-password", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "E-mail é obrigatório." });
  }

  const client = await db.connect();

  try {
    // tenant_id garante que o usuário pertence a uma empresa específica.
    const result = await client.query(
      `SELECT id, tenant_id
       FROM users
       WHERE LOWER(email) = LOWER($1)
         AND active = true
       LIMIT 1`,
      [email]
    );

    // Não revelar se o e-mail existe.
    if (result.rowCount === 0) {
      return res.status(202).json({
        message: "Se o e-mail estiver cadastrado, enviaremos as instruções.",
      });
    }

    const user = result.rows[0];

    // Token aleatório, armazenado apenas em forma hash.
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await client.query(
      `UPDATE password_reset_tokens
       SET used_at = NOW()
       WHERE user_id = $1
         AND used_at IS NULL`,
      [user.id]
    );

    await client.query(
      `INSERT INTO password_reset_tokens
         (user_id, tenant_id, token_hash, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [user.id, user.tenant_id, tokenHash, expiresAt]
    );

    const resetUrl =
      `${process.env.FRONTEND_URL}/reset-password?token=${rawToken}`;

    await mailer.sendMail({
      to: email,
      subject: "Redefinição de senha",
      text: `Acesse o link para redefinir sua senha: ${resetUrl}`,
    });

    return res.status(202).json({
      message: "Se o e-mail estiver cadastrado, enviaremos as instruções.",
    });
  } finally {
    client.release();
  }
});

// POST /auth/reset-password
app.post("/auth/reset-password", async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password) {
    return res.status(400).json({
      error: "Token e nova senha são obrigatórios.",
    });
  }

  if (password.length < 12) {
    return res.status(400).json({
      error: "A senha deve possuir pelo menos 12 caracteres.",
    });
  }

  const tokenHash = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  const client = await db.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT id, user_id, tenant_id
       FROM password_reset_tokens
       WHERE token_hash = $1
         AND used_at IS NULL
         AND expires_at > NOW()
       FOR UPDATE`,
      [tokenHash]
    );

    if (result.rowCount === 0) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Token inválido ou expirado.",
      });
    }

    const reset = result.rows[0];

    const passwordHash = await bcrypt.hash(password, 12);

    // O UPDATE é restrito ao tenant e ao usuário associados
    // ao token, evitando alteração entre empresas.
    await client.query(
      `UPDATE users
       SET password_hash = $1,
           password_changed_at = NOW()
       WHERE id = $2
         AND tenant_id = $3`,
      [passwordHash, reset.user_id, reset.tenant_id]
    );

    await client.query(
      `UPDATE password_reset_tokens
       SET used_at = NOW()
       WHERE id = $1`,
      [reset.id]
    );

    // Opcional: invalidar sessões/refresh tokens existentes.
    await client.query(
      `DELETE FROM refresh_tokens
       WHERE user_id = $1
         AND tenant_id = $2`,
      [reset.user_id, reset.tenant_id]
    );

    await client.query("COMMIT");

    return res.status(200).json({
      message: "Senha alterada com sucesso.",
    });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
});

app.listen(3000);
