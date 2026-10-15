// Node.js + Express
// Exemplo usando criptografia autenticada (AES-256-GCM).
// A chave deve existir apenas em variável de ambiente/secret manager.

const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const KEY = Buffer.from(process.env.ERP_CREDENTIALS_KEY, "base64");
if (KEY.length !== 32) throw new Error("ERP_CREDENTIALS_KEY deve ter 32 bytes");

function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);

  const ciphertext = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64")
  };
}

app.post("/api/erp-credentials", async (req, res) => {
  // tenantId deve vir do contexto autenticado, nunca do body.
  const tenantId = req.user.tenantId;

  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: "username e password são obrigatórios"
    });
  }

  const encryptedUsername = encrypt(username);
  const encryptedPassword = encrypt(password);

  // Persistir em banco:
  // INSERT/UPDATE ... WHERE tenant_id = tenantId
  //
  // Exemplo conceitual:
  await db.erpCredentials.upsert({
    tenantId,
    username: encryptedUsername,
    password: encryptedPassword
  });

  return res.status(204).send();
});

app.listen(3000);
