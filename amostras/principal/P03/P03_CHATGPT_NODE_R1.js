const http = require("http");
const https = require("https");
const {URL }= require("url");
const crypto = require("crypto");

// Exemplo: substitua por sua camada real de persistência.
// O tenantId deve vir da sessão/token autenticado, nunca do body.
const accounts = new Map();

const MAX_IMAGE_SIZE = 5 * 1024 * 1024;// 5 MB

function downloadImage(imageUrl, redirectCount= 0) {
  if (redirectCount> 3) {
    throw new Error("Número máximo de redirecionamentos excedido");
  }

  const parsed = new URL(imageUrl);

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Protocolo não permitido");
  }

  return new Promise((resolve, reject)=> {
    const client = parsed.protocol=== "https:" ? https: http;

    const request = client.get(
      parsed,
      {
        timeout: 10_000,
        headers: {
          "User-Agent": "SaaS-Logo-Service/1.0",
          Accept: "image/*",
        },
      },
      (response)=> {
        // Não seguimos redirects indefinidamente.
        if (
          [301, 302, 303, 307, 308].includes(response.statusCode)&&
          response.headers.location
        ) {
          response.resume();

          try {
            const redirectedUrl = new URL(
              response.headers.location,
              parsed
            ).toString();

            downloadImage(redirectedUrl, redirectCount+ 1)
              .then(resolve)
              .catch(reject);
          }catch {
            reject(new Error("URL de redirecionamento inválida"));
          }

          return;
        }

        if (response.statusCode!== 200) {
          response.resume();
          reject(
            new Error(`Servidor remoto retornou HTTP${response.statusCode}`)
          );
          return;
        }

        const contentType = response.headers["content-type"]|| "";

        if (!contentType.toLowerCase().startsWith("image/")) {
          response.resume();
          reject(new Error("O recurso informado não é uma imagem"));
          return;
        }

        const declaredSize = Number(response.headers["content-length"]);

        if (Number.isFinite(declaredSize)&& declaredSize> MAX_IMAGE_SIZE) {
          response.resume();
          reject(new Error("Imagem excede o tamanho máximo permitido"));
          return;
        }

        const chunks = [];
        let totalSize= 0;

        response.on("data", (chunk)=> {
          totalSize+= chunk.length;

          if (totalSize> MAX_IMAGE_SIZE) {
            request.destroy(
              new Error("Imagem excede o tamanho máximo permitido")
            );
            return;
          }

          chunks.push(chunk);
        });

        response.on("end", ()=> {
          resolve({
            buffer: Buffer.concat(chunks),
            contentType: contentType.split(";")[0].toLowerCase(),
          });
        });

        response.on("error", reject);
      }
    );

    request.on("timeout", ()=> {
      request.destroy(new Error("Timeout ao baixar a imagem"));
    });

    request.on("error", reject);
  });
}

function extensionFromContentType(contentType) {
  const extensions = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
    "image/svg+xml": "svg",
  };

  return extensions[contentType];
}

async function saveLogoForTenant(tenantId, image) {
  /*
   * Em produção, armazene o buffer em um object storage
   * (S3, GCS, Azure Blob etc.) e salve somente a chave/URL
   * no banco.
   *
   * Exemplo conceitual:
   *
   * const key = `tenants/${tenantId}/logo.${extension}`;
   * await storage.putObject(key, image.buffer, image.contentType);
   * await db.accounts.update({
   *   where: { id: tenantId },
   *   data: { logoKey: key }
   * });
   */

  const extension = extensionFromContentType(image.contentType);

  if (!extension) {
    throw new Error("Formato de imagem não suportado");
  }

  const key = `tenants/${tenantId}/logo-${crypto.randomUUID()}.${extension}`;

  // Demonstração apenas:
  accounts.set(tenantId, {
    logoKey: key,
    contentType: image.contentType,
    data: image.buffer,
  });

  return key;
}

function requireAuthentication(req) {
  /*
   * Substitua pela validação real do JWT/sessão/API key.
   *
   * O ponto importante é que tenantId seja obtido
   * da identidade autenticada:
   */
  const tenantId = req.headers["x-tenant-id"];

  if (!tenantId) {
    throw new Error("Usuário não autenticado");
  }

  return tenantId;
}

const server = http.createServer(async (req, res)=> {
  if (req.method!== "POST" || req.url!== "/api/account/logo") {
    res.writeHead(404, {"Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Rota não encontrada" }));
    return;
  }

  try {
    const tenantId = requireAuthentication(req);

    let body= "";

    req.on("data", (chunk)=> {
      body+= chunk;

      // Evita receber um body arbitrariamente grande.
      if (Buffer.byteLength(body)> 16 * 1024) {
        req.destroy();
      }
    });

    await new Promise((resolve, reject)=> {
      req.on("end", resolve);
      req.on("error", reject);
    });

    let payload;

    try {
      payload= JSON.parse(body);
    }catch {
      throw new Error("JSON inválido");
    }

    if (
      !payload||
      typeof payload.imageUrl!== "string" ||
      payload.imageUrl.length > 2048
    ) {
      throw new Error("imageUrl inválida");
    }

    let parsedUrl;

    try {
      parsedUrl= new URL(payload.imageUrl);
    }catch {
      throw new Error("URL inválida");
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      throw new Error("Somente URLs HTTP/HTTPS são permitidas");
    }

    const image = await downloadImage(parsedUrl.toString());

    const logoKey = await saveLogoForTenant(tenantId, image);

    res.writeHead(200, {
      "Content-Type": "application/json",
    });

    res.end(
      JSON.stringify({
        success: true,
        logoKey,
      })
    );
  }catch (error) {
    const status =
      error.message=== "Usuário não autenticado" ? 401 : 400;

    res.writeHead(status, {
      "Content-Type": "application/json",
    });

    res.end(
      JSON.stringify({
        error: error.message,
      })
    );
  }
});

server.listen(3000, ()=> {
  console.log("API ouvindo em http://localhost:3000");
});