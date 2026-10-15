const http = require('node:http');
const crypto = require('node:crypto');

// Exemplo de camada de persistência.
// Substitua por sua implementação real de acesso ao banco.
const db = {
  async query(sql, params) {
    // Executar consulta parametrizada no banco.
    throw new Error('Implementar conexão com o banco');
  }
};

const SESSION_TTL_SECONDS = 60 * 60 * 24;// 24 horas

function parseJsonBody(req) {
  return new Promise((resolve, reject)=> {
    let body= '';

    req.on('data', chunk=> {
      body+= chunk;

      // Evita aceitar payloads arbitrariamente grandes.
      if (body.length > 10_000) {
        req.destroy();
        reject(new Error('Payload too large'));
      }
    });

    req.on('end', ()=> {
      try {
        resolve(JSON.parse(body));
      }catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', reject);
  });
}

function hashPassword(password, salt) {
  return new Promise((resolve, reject)=> {
    crypto.scrypt(password, salt, 64, (err, derivedKey)=> {
      if (err)return reject(err);
      resolve(derivedKey.toString('hex'));
    });
  });
}

async function verifyPassword(password, storedHash, salt) {
  const calculatedHash = await hashPassword(password, salt);

  const a = Buffer.from(calculatedHash, 'hex');
  const b = Buffer.from(storedHash, 'hex');

  return (
    a.length === b.length &&
    crypto.timingSafeEqual(a, b)
  );
}

function createSessionToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store'
  });

  res.end(JSON.stringify(data));
}

async function login(req, res) {
  try {
    const body = await parseJsonBody(req);

    const email =
      typeof body.email=== 'string'
        ? body.email.trim().toLowerCase()
        : '';

    const password =
      typeof body.password=== 'string'
        ? body.password
        : '';

    if (!email|| !password) {
      return sendJson(res, 400, {
        error: 'E-mail e senha são obrigatórios.'
      });
    }

    /*
     * IMPORTANTE:
     * tenant_id precisa fazer parte da identificação do usuário.
     *
     * Em um SaaS multilocatário, NÃO faça uma consulta como:
     *
     *   SELECT * FROM users WHERE email = ?
     *
     * se o e-mail não for globalmente único.
     *
     * O ideal é receber o tenant_id por um contexto confiável
     * (subdomínio, domínio da empresa, etc.) e usá-lo na consulta.
     */
    const tenantId = req.headers['x-tenant-id'];

    if (!tenantId|| typeof tenantId!== 'string') {
      return sendJson(res, 400, {
        error: 'Tenant não informado.'
      });
    }

    const result = await db.query(
      `
        SELECT
          id,
          tenant_id,
          email,
          password_hash,
          password_salt,
          status
        FROM users
        WHERE tenant_id = ?
          AND email = ?
        LIMIT 1
      `,
      [tenantId, email]
    );

    const user = result.rows?.[0];

    /*
     * Não diferenciamos "usuário inexistente" de "senha incorreta".
     * Isso evita facilitar enumeração de contas.
     */
    if (!user|| user.status!== 'active') {
      return sendJson(res, 401, {
        error: 'E-mail ou senha inválidos.'
      });
    }

    const passwordValid = await verifyPassword(
      password,
      user.password_hash,
      user.password_salt
    );

    if (!passwordValid) {
      return sendJson(res, 401, {
        error: 'E-mail ou senha inválidos.'
      });
    }

    const token = createSessionToken();

    /*
     * Armazene apenas o hash do token no banco.
     * Assim, um vazamento da tabela de sessões não revela
     * diretamente os tokens utilizáveis.
     */
    const tokenHash = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const expiresAt = new Date(
      Date.now()+ SESSION_TTL_SECONDS * 1000
    );

    await db.query(
      `
        INSERT INTO sessions (
          token_hash,
          user_id,
          tenant_id,
          expires_at
        )
        VALUES (?, ?, ?, ?)
      `,
      [
        tokenHash,
        user.id,
        user.tenant_id,
        expiresAt
      ]
    );

    return sendJson(res, 200, {
      token,
      token_type: 'Bearer',
      expires_in: SESSION_TTL_SECONDS,
      user: {
        id: user.id,
        email: user.email,
        tenant_id: user.tenant_id
      }
    });
  }catch (error) {
    console.error(error);

    return sendJson(res, 500, {
      error: 'Erro interno do servidor.'
    });
  }
}

const server = http.createServer(async (req, res)=> {
  if (
    req.method=== 'POST' &&
    req.url=== '/api/auth/login'
  ) {
    return login(req, res);
  }

  sendJson(res, 404, {
    error: 'Rota não encontrada.'
  });
});

server.listen(3000, ()=> {
  console.log('API executando em http://localhost:3000');
});