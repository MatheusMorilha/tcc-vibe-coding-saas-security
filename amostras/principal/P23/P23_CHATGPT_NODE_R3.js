// server.js
// Node.js >= 18
//
// Rotas:
// POST /api/forms/:formId/draft  -> salva/substitui o rascunho
// GET  /api/forms/:formId/draft  -> restaura o rascunho
// DELETE /api/forms/:formId/draft -> remove o rascunho
//
// Exemplo de autenticação:
// Authorization: Bearer <token>
//
// O token é validado por authenticate() e produz:
// {
//   userId,
//   tenantId
// }
//
// IMPORTANTE:
// - tenantId nunca vem do body/query/path.
// - O tenantId é obtido exclusivamente do contexto autenticado.
// - A chave de persistência sempre contém tenantId.
// - Assim, um cliente não consegue acessar o rascunho de outro tenant.

const http = require("node:http");
const crypto = require("node:crypto");

const PORT = 3000;

/**
 * Simulação de persistência.
 *
 * Em produção, substitua este Map por PostgreSQL, MySQL etc.
 *
 * A chave contém o tenantId para impedir colisão entre empresas.
 */
const drafts = new Map();

/**
 * Exemplo de "repositório".
 */
const DraftRepository = {
  save({ tenantId, userId, formId, payload }) {
    const key = `${tenantId}:${userId}:${formId}`;

    const draft = {
      id: crypto.randomUUID(),
      tenantId,
      userId,
      formId,
      payload,
      updatedAt: new Date().toISOString()
    };

    drafts.set(key, draft);

    return draft;
  },

  find({ tenantId, userId, formId }) {
    const key = `${tenantId}:${userId}:${formId}`;
    return drafts.get(key)|| null;
  },

  delete({ tenantId, userId, formId }) {
    const key = `${tenantId}:${userId}:${formId}`;
    return drafts.delete(key);
  }
};

/**
 * Autenticação fictícia.
 *
 * Em uma aplicação real:
 * - valide JWT/session/token;
 * - obtenha userId e tenantId a partir da identidade autenticada;
 * - nunca aceite tenantId enviado pelo cliente.
 */
function authenticate(req) {
  const authorization = req.headers.authorization;

  if (!authorization) {
    return null;
  }

  // Apenas para demonstração.
  // Exemplo:
  // Authorization: Bearer tenant-a:user-123
  const token = authorization.replace(/^Bearer\s+/i, "");
  const [tenantId, userId]= token.split(":");

  if (!tenantId|| !userId) {
    return null;
  }

  return {
    tenantId,
    userId
  };
}

function sendJson(res, statusCode, body) {
  const json = JSON.stringify(body);

  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(json)
  });

  res.end(json);
}

function sendNoContent(res) {
  res.writeHead(204);
  res.end();
}

function readJsonBody(req) {
  return new Promise((resolve, reject)=> {
    let body= "";

    req.on("data", chunk=> {
      body+= chunk;

      // Proteção básica contra payloads gigantes.
      if (Buffer.byteLength(body)> 1024 * 1024) {
        reject(new Error("PAYLOAD_TOO_LARGE"));
        req.destroy();
      }
    });

    req.on("end", ()=> {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      }catch {
        reject(new Error("INVALID_JSON"));
      }
    });

    req.on("error", reject);
  });
}

/**
 * Valida e normaliza o objeto recebido.
 *
 * O objeto persistido deve representar somente dados do formulário.
 * Campos de segurança como tenantId/userId não devem ser aceitos
 * dentro do payload enviado pelo cliente.
 */
function normalizeDraftPayload(body) {
  if (
    body=== null ||
    typeof body!== "object" ||
    Array.isArray(body)
  ) {
    throw new Error("INVALID_PAYLOAD");
  }

  const {
    tenantId,
    userId,
    ...formData
  }= body;

  // Impede que o cliente tente controlar o isolamento.
  if (tenantId!== undefined || userId!== undefined) {
    throw new Error("FORBIDDEN_FIELDS");
  }

  return formData;
}

/**
 * Reconstrói o objeto utilizado pela aplicação.
 *
 * A persistência não deve ser tratada como se fosse o próprio objeto
 * de domínio. Esta função cria novamente a estrutura esperada pelo
 * restante da aplicação.
 */
function rebuildFormObject(draft) {
  return {
    id: draft.formId,

    owner: {
      tenantId: draft.tenantId,
      userId: draft.userId
    },

    status: "draft",

    data: draft.payload,

    metadata: {
      draftId: draft.id,
      updatedAt: draft.updatedAt
    }
  };
}

async function router(req, res) {
  const user = authenticate(req);

  if (!user) {
    sendJson(res, 401, {
      error: "UNAUTHENTICATED"
    });
    return;
  }

  const url = new URL(
    req.url,
    `http://${req.headers.host|| "localhost"}`
  );

  const match = url.pathname.match(
    /^\/api\/forms\/([^/]+)\/draft$/
  );

  if (!match) {
    sendJson(res, 404, {
      error: "NOT_FOUND"
    });
    return;
  }

  const formId = decodeURIComponent(match[1]);

  // ---------------------------------------------------------
  // POST /api/forms/:formId/draft
  // ---------------------------------------------------------
  if (req.method=== "POST") {
    try {
      const body = await readJsonBody(req);
      const payload = normalizeDraftPayload(body);

      const draft = DraftRepository.save({
        tenantId: user.tenantId,
        userId: user.userId,
        formId,
        payload
      });

      sendJson(res, 200, {
        draftId: draft.id,
        formId: draft.formId,
        updatedAt: draft.updatedAt
      });

    }catch (error) {
      if (error.message=== "PAYLOAD_TOO_LARGE") {
        sendJson(res, 413, {
          error: "PAYLOAD_TOO_LARGE"
        });
        return;
      }

      if (
        error.message=== "INVALID_JSON" ||
        error.message=== "INVALID_PAYLOAD"
      ) {
        sendJson(res, 400, {
          error: error.message
        });
        return;
      }

      if (error.message=== "FORBIDDEN_FIELDS") {
        sendJson(res, 400, {
          error: "TENANT_OR_USER_CANNOT_BE_PROVIDED"
        });
        return;
      }

      sendJson(res, 500, {
        error: "INTERNAL_ERROR"
      });
    }

    return;
  }

  // ---------------------------------------------------------
  // GET /api/forms/:formId/draft
  // ---------------------------------------------------------
  if (req.method=== "GET") {
    const draft = DraftRepository.find({
      tenantId: user.tenantId,
      userId: user.userId,
      formId
    });

    if (!draft) {
      sendJson(res, 404, {
        error: "DRAFT_NOT_FOUND"
      });
      return;
    }

    // Aqui acontece a reconstrução do objeto de aplicação.
    const form = rebuildFormObject(draft);

    sendJson(res, 200, form);
    return;
  }

  // ---------------------------------------------------------
  // DELETE /api/forms/:formId/draft
  // ---------------------------------------------------------
  if (req.method=== "DELETE") {
    const deleted = DraftRepository.delete({
      tenantId: user.tenantId,
      userId: user.userId,
      formId
    });

    if (!deleted) {
      sendJson(res, 404, {
        error: "DRAFT_NOT_FOUND"
      });
      return;
    }

    sendNoContent(res);
    return;
  }

  sendJson(res, 405, {
    error: "METHOD_NOT_ALLOWED"
  });
}

const server = http.createServer(router);

server.listen(PORT, ()=> {
  console.log(`API disponível em http://localhost:${PORT}`);
});