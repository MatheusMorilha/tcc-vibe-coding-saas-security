const http = require('http');
const crypto = require('crypto');

// Exemplo de camada de persistência.
// Substitua por sua implementação real de banco de dados.
const db = {
  async findUserByEmail(email) {
    // IMPORTANTE:
    // A consulta deve retornar também o tenant_id.
    //
    // Exemplo conceitual:
    //
    // SELECT id, tenant_id, email, password_hash, is_active
    // FROM users
    // WHERE email = ?
    //
    return null;
  },

  async saveSession(session) {
    // INSERT INTO sessions (...)
    // VALUES (...)
  }
};

function hashPassword(password, salt) {
  return crypto
    .scryptSync(password, salt, 64)
    .toString('hex');
}

function verifyPassword(password, storedHash) {
  const [salt, hash]= storedHash.split(':');

  if (!salt|| !hash) {
    return false;
  }

  const calculatedHash = crypto
    .scryptSync(password, salt, 64)
    .toString('hex');

  const a = Buffer.from(calculatedHash, 'hex');
  const b = Buffer.from(hash, 'hex');

  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function parseJsonBody(req) {
  return new Promise((resolve, reject)=> {
    let body= '';

    req.on('data', chunk=> {
      body+= chunk;

      // Evita payloads excessivamente grandes.
      if (body.length > 10_000) {
        reject(new Error('Payload too large'));
        req.destroy();
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

async function login(req, res) {
  try {
    const {email, password }= await parseJsonBody(req);

    if (
      typeof email!== 'string' ||
      typeof password!== 'string' ||
      !email||
      !password
    ) {
      return sendJson(res, 400, {
        error: 'E-mail e senha são obrigatórios.'
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await db.findUserByEmail(normalizedEmail);

    // Não revela se o e-mail existe.
    if (
      !user||
      !user.is_active||
      !verifyPassword(password, user.password_hash)
    ) {
      return sendJson(res, 401, {
        error: 'Credenciais inválidas.'
      });
    }

    const token = generateSessionToken();

    const expiresAt = new Date(
      Date.now()+ 1000 * 60 * 60 * 24
    );

    await db.saveSession({
      token_hash: crypto
        .createHash('sha256')
        .update(token)
        .digest('hex'),

      user_id: user.id,
      tenant_id: user.tenant_id,
      expires_at: expiresAt
    });

    return sendJson(res, 200, {
      token,
      token_type: 'Bearer',
      expires_at: expiresAt.toISOString(),
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

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });

  res.end(JSON.stringify(data));
}

const server = http.createServer(async (req, res)=> {
  if (req.method=== 'POST' && req.url=== '/api/auth/login') {
    return login(req, res);
  }

  sendJson(res, 404, {
    error: 'Rota não encontrada.'
  });
});

server.listen(3000, ()=> {
  console.log('API rodando em http://localhost:3000');
});

function createPasswordHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);

  return `${salt}:${hash}`;
}