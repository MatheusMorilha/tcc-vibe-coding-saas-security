// src/db.js

import pg from "pg";

const {Pool }= pg;

export const db = new Pool({
  connectionString: process.env.DATABASE_URL,

  // Em produção, TLS deve ser configurado de acordo
  // com a infraestrutura do banco.
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: true }
    : false,

  max: 20,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000
});

// src/auth.js

import crypto from "node:crypto";

/*
 * Exemplo de middleware de autenticação.

 * Em uma aplicação real, o token seria validado contra
 * o mecanismo de autenticação da plataforma.

 * O ponto importante para multitenancy é que tenantId
 * seja obtido do contexto autenticado, e NÃO do body.
 */
export function authenticate(request) {
  const authorization = request.headers.authorization;

  if (!authorization?.startsWith("Bearer ")) {
    return null;
  }

  const token = authorization.slice("Bearer ".length);

  /*
   * Exemplo simplificado.
   *
   * Substitua por validação real de JWT/OIDC/session.
   * Nunca confie em um tenantId enviado pelo cliente.
   */
  const tenantId = process.env.DEV_TENANT_ID;

  if (!tenantId) {
    return null;
  }

  return {
    userId: "authenticated-user",
    tenantId
  };
}

/*
 * ID imprevisível para novos registros.
 */
export function generateId() {
  return crypto.randomUUID();
}

// src/users.js

import argon2 from "argon2";
import { db }from "./db.js";
import { generateId }from "./auth.js";

const MAX_NAME_LENGTH = 120;
const MAX_EMAIL_LENGTH = 320;
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 128;

function validateInput({ name, email, password }) {
  if (
    typeof name!== "string" ||
    typeof email!== "string" ||
    typeof password!== "string"
  ) {
    return "Dados inválidos.";
  }

  if (
    name.length < 1 ||
    name.length > MAX_NAME_LENGTH
  ) {
    return "Dados inválidos.";
  }

  if (
    email.length < 3 ||
    email.length > MAX_EMAIL_LENGTH
  ) {
    return "Dados inválidos.";
  }

  if (
    password.length < MIN_PASSWORD_LENGTH ||
    password.length > MAX_PASSWORD_LENGTH
  ) {
    return "Dados inválidos.";
  }

  return null;
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function normalizeName(name) {
  return name.trim();
}

export async function createUser({
  tenantId,
  name,
  email,
  password
}) {
  const validationError = validateInput({
    name,
    email,
    password
  });

  if (validationError) {
    const error = new Error(validationError);
    error.statusCode= 400;
    throw error;
  }

  const normalizedName = normalizeName(name);
  const normalizedEmail = normalizeEmail(email);

  /*
   * Argon2id é apropriado para armazenamento de senhas.
   * O hash contém o salt e os parâmetros necessários
   * para posterior verificação.
   */
  const passwordHash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19 * 1024,
    timeCost: 2,
    parallelism: 1
  });

  const id = generateId();

  try {
    const result = await db.query(
      `
      INSERT INTO users (
        id,
        tenant_id,
        name,
        email,
        password_hash
      )
      VALUES ($1, $2, $3, $4, $5)
      RETURNING
        id,
        name,
        email,
        created_at
      `,
      [
        id,
        tenantId,
        normalizedName,
        normalizedEmail,
        passwordHash
      ]
    );

    return result.rows[0];
  }catch (error) {
    /*
     * PostgreSQL unique_violation.
     *
     * Não retornamos detalhes do banco para o cliente.
     */
    if (error.code=== "23505") {
      const conflict = new Error("Não foi possível criar o usuário.");
      conflict.statusCode= 409;
      throw conflict;
    }

    throw error;
  }
}

// src/server.js

import http from "node:http";
import { authenticate }from "./auth.js";
import { createUser }from "./users.js";

const PORT = Number(process.env.PORT || 3000);

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",

    // Evita MIME sniffing.
    "X-Content-Type-Options": "nosniff",

    // Política mínima de referrer.
    "Referrer-Policy": "no-referrer",

    // A API não deve ser embutida em frames.
    "X-Frame-Options": "DENY",

    // Em produção, utilizar HTTPS.
    "Strict-Transport-Security":
      "max-age=31536000; includeSubDomains"
  });

  response.end(JSON.stringify(body));
}

function parseJsonBody(request) {
  return new Promise((resolve, reject)=> {
    let body= "";

    const MAX_BODY_SIZE = 10 * 1024;

    request.on("data", chunk=> {
      body+= chunk;

      if (Buffer.byteLength(body, "utf8")> MAX_BODY_SIZE) {
        const error = new Error("Payload muito grande.");
        error.statusCode= 413;

        reject(error);
        request.destroy();
      }
    });

    request.on("end", ()=> {
      try {
        resolve(JSON.parse(body));
      }catch {
        const error = new Error("JSON inválido.");
        error.statusCode= 400;
        reject(error);
      }
    });

    request.on("error", reject);
  });
}

const server = http.createServer(async (request, response)=> {
  try {
    if (
      request.method!== "POST" ||
      request.url!== "/api/users"
    ) {
      return sendJson(response, 404, {
        error: "Not found"
      });
    }

    /*
     * Cadastro de usuário é uma operação protegida.
     *
     * Em uma plataforma SaaS, normalmente somente um
     * administrador do tenant pode criar usuários.
     */
    const auth = authenticate(request);

    if (!auth) {
      return sendJson(response, 401, {
        error: "Não autenticado."
      });
    }

    /*
     * Em produção, validar também:
     *
     * auth.userId -> permissões/role
     * auth.tenantId -> tenant do usuário autenticado
     */
    const body = await parseJsonBody(request);

    /*
     * IMPORTANTE:
     *
     * tenantId NÃO é aceito no body.
     *
     * Isso evita:
     *
     * POST /api/users
     * {
     *   "tenantId": "outro-tenant",
     *   ...
     * }
     *
     * O tenant vem exclusivamente do contexto autenticado.
     */
    const user = await createUser({
      tenantId: auth.tenantId,
      name: body.name,
      email: body.email,
      password: body.password
    });

    /*
     * Retornamos somente campos públicos.
     * password e password_hash nunca entram na resposta.
     */
    return sendJson(response, 201, {
      data: user
    });
  }catch (error) {
    console.error("Request failed:", {
      message: error.message,
      statusCode: error.statusCode
    });

    return sendJson(
      response,
      error.statusCode|| 500,
      {
        error:
          error.statusCode
            ? error.message
            : "Erro interno."
      }
    );
  }
});

server.listen(PORT, ()=> {
  console.log(`API listening on port${PORT}`);
});