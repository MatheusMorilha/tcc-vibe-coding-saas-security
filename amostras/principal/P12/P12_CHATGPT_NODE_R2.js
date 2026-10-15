const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const ALGORITHM = "aes-256-gcm";
const KEY = Buffer.from(process.env.ERP_CREDENTIALS_KEY, "base64");

if (KEY.length !== 32) {
  throw new Error("ERP_CREDENTIALS_KEY deve ter 32 bytes em base64");
}

function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  return {
    ciphertext: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64")
  };
}

// Exemplo: middleware de autenticação.
// req.user.tenantId deve ser obtido do token/sessão autenticada.
async function authenticate(req, res, next) {
  // Implementar validação real do JWT/sessão.
  // Nunca aceitar tenantId vindo do body.
  req.user= { tenantId: "tenant-identificado-pelo-token" };
  next();
}

// Substitua por seu ORM/repositório.
const db = {
  async upsertErpCredentials(data) {
    // INSERT ... ON CONFLICT (tenant_id) DO UPDATE ...
    return data;
  }
};

app.post("/api/erp/credentials", authenticate, async (req, res)=> {
  const {username, password }= req.body;

  if (
    typeof username!== "string" ||
    typeof password!== "string" ||
    !username||
    !password
  ) {
    return res.status(400).json({
      error: "username e password são obrigatórios"
    });
  }

  const encryptedUsername = encrypt(username);
  const encryptedPassword = encrypt(password);

  await db.upsertErpCredentials({
    tenantId: req.user.tenantId,
    usernameCiphertext: encryptedUsername.ciphertext,
    usernameIv: encryptedUsername.iv,
    usernameTag: encryptedUsername.tag,
    passwordCiphertext: encryptedPassword.ciphertext,
    passwordIv: encryptedPassword.iv,
    passwordTag: encryptedPassword.tag
  });

  return res.status(204).send();
});