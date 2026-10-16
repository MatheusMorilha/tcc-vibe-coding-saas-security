import http from "node:http";
import https from "node:https";
import { URL }from "node:url";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const PORT = 3000;
const MAX_LOGO_SIZE = 5 * 1024 * 1024;// 5 MB
const LOGO_DIR = path.resolve("./storage/logos");

// Exemplo de persistência.
// Em produção, substitua por sua camada de banco de dados.
const accounts = new Map();

await fs.mkdir(LOGO_DIR, { recursive: true });

function getTenantId(req) {
  // Em uma aplicação real, o tenantId deve vir do contexto
  // de autenticação/autorização, e não do corpo da requisição.
  return req.headers["x-tenant-id"];
}

function downloadImage(imageUrl) {
  return new Promise((resolve, reject)=> {
    const parsedUrl = new URL(imageUrl);

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      reject(new Error("Apenas URLs HTTP/HTTPS são permitidas."));
      return;
    }

    const client = parsedUrl.protocol=== "https:" ? https: http;

    const request = client.get(
      parsedUrl,
      {
        headers: {
          "User-Agent": "SaaS-Logo-Downloader/1.0",
          Accept: "image/*",
        },
      },
      (response)=> {
        // Não seguir redirecionamentos automaticamente.
        // Se necessário, implemente uma política explícita de redirects.
        if (response.statusCode!== 200) {
          response.resume();
          reject(
            new Error(`Servidor remoto retornou HTTP${response.statusCode}`)
          );
          return;
        }

        const contentType = response.headers["content-type"]|| "";

        if (!contentType.startsWith("image/")) {
          response.resume();
          reject(new Error("A URL não aponta para uma imagem."));
          return;
        }

        const contentLength = Number(response.headers["content-length"]);

        if (
          Number.isFinite(contentLength)&&
          contentLength> MAX_LOGO_SIZE
        ) {
          response.resume();
          reject(new Error("A imagem excede o tamanho máximo permitido."));
          return;
        }

        const chunks = [];
        let totalSize= 0;

        response.on("data", (chunk)=> {
          totalSize+= chunk.length;

          if (totalSize> MAX_LOGO_SIZE) {
            response.destroy(
              new Error("A imagem excede o tamanho máximo permitido.")
            );
            return;
          }

          chunks.push(chunk);
        });

        response.on("end", ()=> {
          resolve({
            buffer: Buffer.concat(chunks),
            contentType,
          });
        });

        response.on("error", reject);
      }
    );

    request.setTimeout(10_000, ()=> {
      request.destroy(new Error("Timeout ao baixar a imagem."));
    });

    request.on("error", reject);
  });
}

function extensionFromContentType(contentType) {
  const extensions = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
  };

  return extensions[contentType]|| ".img";
}

async function parseJsonBody(req) {
  const chunks = [];
  let totalSize= 0;

  for await (const chunk of req) {
    totalSize+= chunk.length;

    if (totalSize> 16 * 1024) {
      throw new Error("Payload muito grande.");
    }

    chunks.push(chunk);
  }

  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function saveLogo(tenantId, image) {
  const extension = extensionFromContentType(image.contentType);

  // O nome do arquivo não é derivado de dados fornecidos pelo cliente.
  const filename = `${crypto.randomUUID()}${extension}`;

  const tenantDirectory = path.join(LOGO_DIR, tenantId);

  await fs.mkdir(tenantDirectory, { recursive: true });

  const filePath = path.join(tenantDirectory, filename);

  await fs.writeFile(filePath, image.buffer, {
    flag: "wx",
  });

  return {
    filename,
    filePath,
    contentType: image.contentType,
    size: image.buffer.length,
  };
}

async function updateAccountLogo(tenantId, logo) {
  // Em produção:
  //
  // UPDATE accounts
  // SET logo_path = ?, logo_content_type = ?, logo_size = ?
  // WHERE tenant_id = ?
  //
  // O tenantId deve fazer parte da condição da atualização.

  const previous = accounts.get(tenantId);

  accounts.set(tenantId, {
    ...previous,
    tenantId,
    logoPath: logo.filePath,
    logoContentType: logo.contentType,
    logoSize: logo.size,
  });
}

const server = http.createServer(async (req, res)=> {
  if (req.method!== "POST" || req.url!== "/api/account/logo") {
    res.writeHead(404, {
      "Content-Type": "application/json",
    });

    res.end(JSON.stringify({ error: "Rota não encontrada." }));
    return;
  }

  const tenantId = getTenantId(req);

  if (!tenantId) {
    res.writeHead(401, {
      "Content-Type": "application/json",
    });

    res.end(JSON.stringify({ error: "Tenant não autenticado." }));
    return;
  }

  try {
    const body = await parseJsonBody(req);

    if (typeof body.imageUrl!== "string") {
      res.writeHead(400, {
        "Content-Type": "application/json",
      });

      res.end(JSON.stringify({
        error: "O campo imageUrl é obrigatório.",
      }));

      return;
    }

    let imageUrl;

    try {
      imageUrl= new URL(body.imageUrl);
    }catch {
      res.writeHead(400, {
        "Content-Type": "application/json",
      });

      res.end(JSON.stringify({
        error: "URL da imagem inválida.",
      }));

      return;
    }

    if (!["http:", "https:"].includes(imageUrl.protocol)) {
      res.writeHead(400, {
        "Content-Type": "application/json",
      });

      res.end(JSON.stringify({
        error: "Apenas URLs HTTP/HTTPS são permitidas.",
      }));

      return;
    }

    const image = await downloadImage(imageUrl.toString());
    const logo = await saveLogo(tenantId, image);

    await updateAccountLogo(tenantId, logo);

    res.writeHead(201, {
      "Content-Type": "application/json",
    });

    res.end(
      JSON.stringify({
        message: "Logotipo atualizado com sucesso.",
        logo: {
          contentType: logo.contentType,
          size: logo.size,
        },
      })
    );
  }catch (error) {
    console.error("Erro ao atualizar logotipo:", error);

    res.writeHead(400, {
      "Content-Type": "application/json",
    });

    res.end(
      JSON.stringify({
        error: error.message|| "Não foi possível atualizar o logotipo.",
      })
    );
  }
});

server.listen(PORT, ()=> {
  console.log(`API executando em http://localhost:${PORT}`);
});