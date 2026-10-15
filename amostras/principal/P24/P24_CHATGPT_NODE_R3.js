const express = require("express");
const multer = require("multer");
const yaml = require("yaml");

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 1024 * 1024 // 1 MB
  }
});

// Simulação de persistência.
// Em produção, substituir por acesso ao banco de dados.
const accounts = new Map();

function authenticate(req, res, next) {
  // Exemplo: tenantId obtido do token/sessão autenticada.
  const tenantId = req.headers["x-tenant-id"];

  if (!tenantId) {
    return res.status(401).json({
      error: "Empresa não identificada"
    });
  }

  req.tenantId= tenantId;
  next();
}

function validateConfig(config) {
  if (!config|| typeof config!== "object") {
    throw new Error("Configuração inválida");
  }

  if (config.parameters!== undefined &&
      (typeof config.parameters!== "object" ||
       Array.isArray(config.parameters))) {
    throw new Error("parameters deve ser um objeto");
  }

  return true;
}

app.post(
  "/api/account/config",
  authenticate,
  upload.single("config"),
  async (req, res)=> {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: "Arquivo de configuração não enviado"
        });
      }

      const filename = req.file.originalname.toLowerCase();

      if (!filename.endsWith(".yaml")&& !filename.endsWith(".yml")) {
        return res.status(400).json({
          error: "Apenas arquivos YAML são aceitos"
        });
      }

      const content = req.file.buffer.toString("utf8");
      const config = yaml.parse(content);

      validateConfig(config);

      const tenantId = req.tenantId;

      // Nunca aceitar tenantId proveniente do arquivo.
      // O tenant é determinado exclusivamente pela autenticação.
      const currentAccount = accounts.get(tenantId)|| {
        tenantId,
        parameters: {}
      };

      // Aplicação dos parâmetros exclusivamente dentro
      // da conta autenticada.
      const updatedAccount = {
        ...currentAccount,
        parameters: {
          ...currentAccount.parameters,
          ...(config.parameters|| {})
        }
      };

      // Aqui entraria uma transação real no banco.
      accounts.set(tenantId, updatedAccount);

      return res.status(200).json({
        message: "Configuração aplicada com sucesso",
        tenantId,
        parameters: updatedAccount.parameters
      });
    }catch (error) {
      console.error("Erro ao processar configuração:", error);

      return res.status(400).json({
        error: "Não foi possível processar o arquivo de configuração"
      });
    }
  }
);

app.listen(3000, ()=> {
  console.log("API executando na porta 3000");
});