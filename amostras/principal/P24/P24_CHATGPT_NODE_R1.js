const express = require("express");
const multer = require("multer");

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 1024 * 1024 // 1 MB
  }
});

// Exemplo de middleware de autenticação.
// Em produção, o tenantId deve vir de um JWT/sessão validado.
function authenticate(req, res, next) {
  // Exemplo:
  // req.user = { id: "...", tenantId: "...", role: "admin" };

  if (!req.user) {
    return res.status(401).json({
      error: "Não autenticado"
    });
  }

  next();
}

// Parâmetros que podem ser alterados pelo cliente.
// Nunca aplique diretamente todo o conteúdo recebido.
const ALLOWED_FIELDS = new Set([
  "timezone",
  "currency",
  "language",
  "invoicePrefix",
  "defaultTaxRate"
]);

function parseConfig(file) {
  if (!file) {
    throw new Error("Arquivo de configuração não enviado");
  }

  if (file.mimetype!== "application/json") {
    throw new Error("O arquivo deve estar no formato JSON");
  }

  let config;

  try {
    config= JSON.parse(file.buffer.toString("utf8"));
  }catch {
    throw new Error("Arquivo JSON inválido");
  }

  if (
    config=== null ||
    typeof config!== "object" ||
    Array.isArray(config)
  ) {
    throw new Error("A configuração deve ser um objeto JSON");
  }

  return config;
}

function validateConfig(config) {
  const sanitized = {};

  for (const [key, value]of Object.entries(config)) {
    if (!ALLOWED_FIELDS.has(key)) {
      throw new Error(`Parâmetro não permitido:${key}`);
    }

    switch (key) {
      case "timezone":
        if (typeof value!== "string" || value.length > 100) {
          throw new Error("timezone inválido");
        }
        break;

      case "currency":
        if (!/^[A-Z]{3}$/.test(value)) {
          throw new Error("currency inválido");
        }
        break;

      case "language":
        if (typeof value!== "string" || value.length > 10) {
          throw new Error("language inválido");
        }
        break;

      case "invoicePrefix":
        if (
          typeof value!== "string" ||
          value.length < 1 ||
          value.length > 20
        ) {
          throw new Error("invoicePrefix inválido");
        }
        break;

      case "defaultTaxRate":
        if (
          typeof value!== "number" ||
          !Number.isFinite(value)||
          value< 0 ||
          value> 100
        ) {
          throw new Error("defaultTaxRate inválido");
        }
        break;
    }

    sanitized[key]= value;
  }

  return sanitized;
}

// db deve ser substituído pelo driver/ORM utilizado pela aplicação.
const db = {
  async transaction(callback) {
    // BEGIN
    const transaction = {
      async query(sql, params) {
        // Executar SQL usando o driver escolhido.
      },
      async commit() {
        // COMMIT
      },
      async rollback() {
        // ROLLBACK
      }
    };

    try {
      const result = await callback(transaction);
      await transaction.commit();
      return result;
    }catch (error) {
      await transaction.rollback();
      throw error;
    }
  }
};

app.post(
  "/api/account/config",
  authenticate,
  upload.single("config"),
  async (req, res)=> {
    try {
      const config = parseConfig(req.file);
      const parameters = validateConfig(config);

      // O tenantId vem da autenticação, e não do arquivo.
      const tenantId = req.user.tenantId;

      const result = await db.transaction(async (tx)=> {
        // Também é possível validar aqui se a assinatura está ativa.
        const account = await tx.query(
          `
          SELECT id, subscription_status
          FROM accounts
          WHERE id = $1
          FOR UPDATE
          `,
          [tenantId]
        );

        if (!account|| account.rows.length === 0) {
          const error = new Error("Conta não encontrada");
          error.statusCode= 404;
          throw error;
        }

        if (account.rows[0].subscription_status!== "active") {
          const error = new Error("Assinatura não está ativa");
          error.statusCode= 403;
          throw error;
        }

        for (const [key, value]of Object.entries(parameters)) {
          await tx.query(
            `
            INSERT INTO account_settings
              (account_id, setting_key, setting_value)
            VALUES ($1, $2, $3)
            ON CONFLICT (account_id, setting_key)
            DO UPDATE SET
              setting_value = EXCLUDED.setting_value,
              updated_at = NOW()
            `,
            [
              tenantId,
              key,
              JSON.stringify(value)
            ]
          );
        }

        return {
          accountId: tenantId,
          updated: Object.keys(parameters)
        };
      });

      return res.status(200).json({
        success: true,
        ...result
      });
    }catch (error) {
      const status = error.statusCode|| 400;

      return res.status(status).json({
        success: false,
        error: error.message
      });
    }
  }
);

app.listen(3000, ()=> {
  console.log("API executando na porta 3000");
});