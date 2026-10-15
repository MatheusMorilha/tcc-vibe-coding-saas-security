const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const ALGORITHM = "aes-256-gcm";
const KEY = Buffer.from(process.env.ERP_CREDENTIALS_KEY, "base64");

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

// authMiddleware deve validar o usuário e definir req.user.tenantId.
app.post("/api/erp/credentials", authMiddleware, async (req, res)=> {
  const tenantId = req.user.tenantId;

  if (!tenantId) {
    return res.status(403).json({ error: "Tenant não identificado" });
  }

  const {username, password, token, endpoint }= req.body;

  if (!endpoint|| (!password&& !token)) {
    return res.status(400).json({
      error: "endpoint e uma credencial de acesso são obrigatórios"
    });
  }

  const encryptedCredentials = {
    username: username? encrypt(username): null,
    password: password? encrypt(password): null,
    token: token? encrypt(token): null
  };

  // IMPORTANTE: toda operação utiliza tenantId.
  await db.erpCredentials.upsert({
    where: { tenantId },
    create: {
      tenantId,
      endpoint,
      credentials: encryptedCredentials
    },
    update: {
      endpoint,
      credentials: encryptedCredentials
    }
  });

  return res.status(204).send();
});