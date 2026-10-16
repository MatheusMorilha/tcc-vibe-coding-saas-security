'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

// Exemplo de repositório. Em produção, substitua por seu driver SQL/ORM.
const db = {
  async userExistsByEmail(tenantId, email) {
    // SELECT 1 FROM users WHERE tenant_id = ? AND email = ? LIMIT 1
    throw new Error('Implementar acesso ao banco');
  },

  async createUser({ id, tenantId, name, email, passwordHash }) {
    // INSERT INTO users
    // (id, tenant_id, name, email, password_hash)
    // VALUES (?, ?, ?, ?, ?)
    throw new Error('Implementar acesso ao banco');
  }
};

const PASSWORD = {
  // scrypt é disponibilizado nativamente pelo Node.js.
  // N=2^15, r=8, p=3 é um ponto de partida; calibre conforme sua infraestrutura.
  N: 32768,
  r: 8,
  p: 3,
  keyLength: 64,
  saltLength: 16
};

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function validateInput(body) {
  if (!body || typeof body !== 'object') {
    return 'Corpo da requisição inválido.';
  }

  if (
    typeof body.name !== 'string' ||
    typeof body.email !== 'string' ||
    typeof body.password !== 'string'
  ) {
    return 'Nome, e-mail e senha são obrigatórios.';
  }

  const name = body.name.trim();
  const email = normalizeEmail(body.email);

  if (name.length < 2 || name.length > 120) {
    return 'Nome inválido.';
  }

  // Validação básica; a confirmação real deve ocorrer por e-mail.
  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return 'E-mail inválido.';
  }

  if (body.password.length < 12 || body.password.length > 128) {
    return 'A senha deve ter entre 12 e 128 caracteres.';
  }

  return null;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(PASSWORD.saltLength);

  return new Promise((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      PASSWORD.keyLength,
      {
        N: PASSWORD.N,
        r: PASSWORD.r,
        p: PASSWORD.p
      },
      (error, derivedKey) => {
        if (error) return reject(error);

        resolve([
          'scrypt',
          PASSWORD.N,
          PASSWORD.r,
          PASSWORD.p,
          salt.toString('base64url'),
          derivedKey.toString('base64url')
        ].join('$'));
      }
    );
  });
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });

  res.end(JSON.stringify(payload));
}

async function readJsonBody(req) {
  const MAX_BODY_SIZE = 16 * 1024;
  let size = 0;
  let raw = '';

  for await (const chunk of req) {
    size += Buffer.byteLength(chunk);

    if (size > MAX_BODY_SIZE) {
      const error = new Error('Payload muito grande.');
      error.statusCode = 413;
      throw error;
    }

    raw += chunk;
  }

  try {
    return JSON.parse(raw);
  } catch {
    const error = new Error('JSON inválido.');
    error.statusCode = 400;
    throw error;
  }
}

/*
 * Exemplo de contexto obtido pelo middleware de autenticação.
 *
 * IMPORTANTE:
 * Não faça:
 *   const tenantId = req.body.tenantId;
 *
 * O tenant deve ser determinado pelo token/sessão autenticada.
 */
async function authenticateRequest(req) {
  // Exemplo:
  //
  // const token = req.headers.authorization?.replace('Bearer ', '');
  // const session = await verifyAccessToken(token);
  //
  // return {
  //   userId: session.sub,
  //   tenantId: session.tenantId,
  //   role: session.role
  // };

  return {
    userId: 'authenticated-user-id',
    tenantId: 'authenticated-tenant-id',
    role: 'admin'
  };
}

async function createUserHandler(req, res) {
  try {
    if (req.method !== 'POST' || req.url !== '/api/users') {
      return sendJson(res, 404, {
        error: 'Not found'
      });
    }

    const contentType = req.headers['content-type'] || '';

    if (!contentType.startsWith('application/json')) {
      return sendJson(res, 415, {
        error: 'Content-Type deve ser application/json.'
      });
    }

    // 1. Autenticação/autorização.
    const auth = await authenticateRequest(req);

    if (!auth?.tenantId || !auth?.userId) {
      return sendJson(res, 401, {
        error: 'Não autenticado.'
      });
    }

    // Exemplo de controle de privilégio.
    if (!['admin', 'owner'].includes(auth.role)) {
      return sendJson(res, 403, {
        error: 'Sem permissão para cadastrar usuários.'
      });
    }

    // 2. Ler e validar entrada.
    const body = await readJsonBody(req);
    const validationError = validateInput(body);

    if (validationError) {
      return sendJson(res, 400, {
        error: validationError
      });
    }

    const name = body.name.trim();
    const email = normalizeEmail(body.email);

    // 3. Verificar unicidade dentro do tenant.
    const existingUser = await db.userExistsByEmail(
      auth.tenantId,
      email
    );

    if (existingUser) {
      return sendJson(res, 409, {
        error: 'Não foi possível criar o usuário.'
      });
    }

    // 4. Nunca armazenar senha em texto puro.
    const passwordHash = await hashPassword(body.password);

    // 5. ID gerado no servidor.
    const userId = crypto.randomUUID();

    await db.createUser({
      id: userId,
      tenantId: auth.tenantId,
      name,
      email,
      passwordHash
    });

    // 6. Nunca retornar password/passwordHash.
    return sendJson(res, 201, {
      id: userId,
      name,
      email,
      tenantId: auth.tenantId
    });
  } catch (error) {
    // Não exponha stack trace ou detalhes internos ao cliente.
    console.error(error);

    if (error.statusCode) {
      return sendJson(res, error.statusCode, {
        error: error.message
      });
    }

    return sendJson(res, 500, {
      error: 'Erro interno do servidor.'
    });
  }
}

const server = http.createServer(createUserHandler);

server.listen(3000, () => {
  console.log('API ouvindo na porta 3000');
});
