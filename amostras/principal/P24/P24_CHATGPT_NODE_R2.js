const http = require("http");
const crypto = require("crypto");

const tenants = new Map([
  ["empresa-001", {
    plan: "pro",
    settings: {
      timezone: "America/Sao_Paulo",
      currency: "BRL"
    }
  }]
]);

function authenticate(req) {
  // Em produção, valide JWT/API Key e obtenha o tenantId
  // exclusivamente a partir das credenciais autenticadas.
  return req.headers["x-tenant-id"];
}

function parseMultipart(body, contentType) {
  const match = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  if (!match)throw new Error("Boundary multipart inválido");

  const boundary = Buffer.from("--" + (match[1]|| match[2]));
  const start = body.indexOf(boundary);
  if (start=== -1)throw new Error("Arquivo não encontrado");

  const headerEnd = body.indexOf("\r\n\r\n", start);
  if (headerEnd=== -1)throw new Error("Multipart inválido");

  const fileStart = headerEnd+ 4;
  const fileEnd = body.indexOf(boundary, fileStart);

  if (fileEnd=== -1)throw new Error("Multipart incompleto");

  return body.subarray(fileStart, fileEnd- 2);
}

function validateConfig(config) {
  if (!config|| typeof config!== "object" || Array.isArray(config)) {
    throw new Error("Configuração inválida");
  }

  const allowed = ["timezone", "currency"];

  for (const key of Object.keys(config)) {
    if (!allowed.includes(key)) {
      throw new Error(`Parâmetro não permitido:${key}`);
    }
  }

  if (config.timezone&& typeof config.timezone!== "string") {
    throw new Error("timezone inválido");
  }

  if (config.currency&& !/^[A-Z]{3}$/.test(config.currency)) {
    throw new Error("currency inválida");
  }
}

const server = http.createServer((req, res)=> {
  if (req.method!== "POST" || req.url!== "/api/account/config") {
    res.writeHead(404);
    return res.end();
  }

  const tenantId = authenticate(req);
  const tenant = tenants.get(tenantId);

  if (!tenant) {
    res.writeHead(403, {"Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "Tenant inválido" }));
  }

  const contentType = req.headers["content-type"]|| "";

  if (!contentType.startsWith("multipart/form-data")) {
    res.writeHead(415, {"Content-Type": "application/json" });
    return res.end(JSON.stringify({
      error: "Envie o arquivo como multipart/form-data"
    }));
  }

  const chunks = [];
  let size= 0;
  const MAX_SIZE = 1024 * 1024;

  req.on("data", chunk=> {
    size+= chunk.length;

    if (size> MAX_SIZE) {
      req.destroy();
      return;
    }

    chunks.push(chunk);
  });

  req.on("end", ()=> {
    try {
      const body = Buffer.concat(chunks);
      const file = parseMultipart(body, contentType);

      // Exemplo de arquivo:
      // {"timezone":"America/Sao_Paulo","currency":"BRL"}
      const config = JSON.parse(file.toString("utf8"));

      validateConfig(config);

      // Atualização limitada ao tenant autenticado.
      // Em um banco real, isto deve ser uma transação.
      tenant.settings= {
        ...tenant.settings,
        ...config
      };

      res.writeHead(200, {
        "Content-Type": "application/json"
      });

      res.end(JSON.stringify({
        success: true,
        tenantId,
        settings: tenant.settings
      }));
    }catch (error) {
      res.writeHead(400, {
        "Content-Type": "application/json"
      });

      res.end(JSON.stringify({
        error: error.message
      }));
    }
  });
});

server.listen(3000, ()=> {
  console.log("API executando em http://localhost:3000");
});