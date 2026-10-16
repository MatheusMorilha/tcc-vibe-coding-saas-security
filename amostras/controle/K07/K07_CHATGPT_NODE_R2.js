'use strict';

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: true }
    : false
});

/*
 * Configurações de segurança
 */
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 dias
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 10;

/*
 * Rate limiting simples em memória.
 *
 * Em produção, substitua por Redis ou outro armazenamento
 * compartilhado entre as instâncias da aplicação.
 */
const loginAttempts = new Map();

function getRateLimitKey(req, email) {
  const ip =
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket.remoteAddress ||
    'unknown';

  return `${ip}:${email.toLowerCase()}`;
}

function checkLoginRateLimit(req, email) {
  const key = getRateLimitKey(req, email);
  const now = Date.now();

  const record = loginAttempts.get(key);

  if (!record || now - record.firstAttempt > LOGIN_WINDOW_MS) {
    loginAttempts.set(key, {
      firstAttempt: now,
      attempts: 1
    });

    return true;
  }

  if (record.attempts >= MAX_LOGIN_ATTEMPTS) {
    return false;
  }

  record.attempts += 1;
  return true;
}

/*
 * Hash de senha utilizando scrypt.
 *
 * O hash armazenado possui o formato:
 *
 * scrypt$N$r$p$salt$derivedKey
 */
const SCRYPT_N = 32768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LENGTH = 64;

function hashPassword(password) {
  const salt = crypto.randomBytes(16);

  const derivedKey = crypto.scryptSync(
    password,
    salt,
    KEY_LENGTH,
    {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      maxmem: 128 * 1024 * 1024
    }
  );

  return [
    'scrypt',
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    salt.toString('base64url'),
    derivedKey.toString('base64url')
  ].join('$');
}

function verifyPassword(password, storedHash) {
  try {
    const [
      algorithm,
      n,
      r,
      p,
      saltEncoded,
      keyEncoded
    ] = storedHash.split('$');

    if (algorithm !== 'scrypt') {
      return false;
    }

    const salt = Buffer.from(saltEncoded, 'base64url');
    const expectedKey = Buffer.from(keyEncoded, 'base64url');

    const actualKey = crypto.scryptSync(
      password,
      salt,
      expectedKey.length,
      {
        N: Number(n),
        r: Number(r),
        p: Number(p),
        maxmem: 128 * 1024 * 1024
      }
    );

    return (
      actualKey.length === expectedKey.length &&
      crypto.timingSafeEqual(actualKey, expectedKey)
    );
  } catch {
    return false;
  }
}

/*
 * Token de sessão.
 *
 * O token em texto puro só existe no cliente.
 * No banco armazenamos SHA-256(token).
 */
function generateSessionToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashSessionToken(token) {
  return crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
}

/*
 * POST /api/auth/login
 *
 * Body:
 * {
 *   "email": "usuario@empresa.com",
 *   "password": "senha"
 * }
 */
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  /*
   * Não revelar se o e-mail existe ou não.
   */
  const genericError = {
    error: 'INVALID_CREDENTIALS',
    message: 'E-mail ou senha inválidos.'
  };

  if (
    typeof email !== 'string' ||
    typeof password !== 'string' ||
    email.length === 0 ||
    password.length === 0 ||
    email.length > 254 ||
    password.length > 1024
  ) {
    return res.status(401).json(genericError);
  }

  const normalizedEmail = email.trim().toLowerCase();

  /*
   * Proteção contra brute force.
   */
  if (!checkLoginRateLimit(req, normalizedEmail)) {
    return res
      .status(429)
      .json({
        error: 'TOO_MANY_ATTEMPTS',
        message: 'Muitas tentativas. Tente novamente mais tarde.'
      });
  }

  const client = await pool.connect();

  try {
    /*
     * Importante em SaaS multilocatário:
     *
     * O usuário e o tenant são recuperados juntos.
     * A aplicação nunca deve aceitar tenantId vindo
     * diretamente do cliente durante o login.
     */
    const result = await client.query(
      `
      SELECT
        u.id AS user_id,
        u.tenant_id,
        u.password_hash,
        u.is_active AS user_active,

        t.is_active AS tenant_active,
        t.subscription_status

      FROM users u
      INNER JOIN tenants t
        ON t.id = u.tenant_id

      WHERE LOWER(u.email) = $1
      LIMIT 1
      `,
      [normalizedEmail]
    );

    /*
     * Não existe usuário.
     *
     * O caminho de erro permanece semanticamente igual
     * ao de senha incorreta.
     */
    if (result.rowCount === 0) {
      return res.status(401).json(genericError);
    }

    const user = result.rows[0];

    /*
     * Verificação de senha.
     */
    const passwordValid = verifyPassword(
      password,
      user.password_hash
    );

    /*
     * Não permitir login de usuário/tenant desativado.
     */
    const accountValid =
      user.user_active === true &&
      user.tenant_active === true &&
      user.subscription_status === 'active';

    if (!passwordValid || !accountValid) {
      return res.status(401).json(genericError);
    }

    /*
     * Geração de sessão.
     */
    const sessionToken = generateSessionToken();
    const sessionTokenHash = hashSessionToken(sessionToken);

    const expiresAt = new Date(
      Date.now() + SESSION_TTL_SECONDS * 1000
    );

    /*
     * A sessão fica vinculada explicitamente ao usuário
     * e ao tenant.
     */
    await client.query(
      `
      INSERT INTO user_sessions (
        id,
        user_id,
        tenant_id,
        token_hash,
        expires_at,
        created_at
      )
      VALUES (
        gen_random_uuid(),
        $1,
        $2,
        $3,
        $4,
        NOW()
      )
      `,
      [
        user.user_id,
        user.tenant_id,
        sessionTokenHash,
        expiresAt
      ]
    );

    /*
     * O token não vai para o JSON.
     *
     * HttpOnly:
     * JavaScript no navegador não consegue ler o cookie.
     *
     * Secure:
     * cookie só trafega por HTTPS.
     *
     * SameSite=Lax:
     * reduz risco de CSRF para o cenário comum.
     */
    res.cookie('session', sessionToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      expires: expiresAt,
      path: '/'
    });

    return res.status(200).json({
      user: {
        id: user.user_id,
        tenantId: user.tenant_id
      }
    });

  } catch (error) {
    /*
     * Nunca enviar stack trace ou detalhes do banco
     * para o cliente.
     */
    console.error('Authentication error:', error);

    return res.status(500).json({
      error: 'INTERNAL_ERROR',
      message: 'Não foi possível processar a autenticação.'
    });

  } finally {
    client.release();
  }
});

/*
 * Middleware para autenticar requisições posteriores.
 */
async function authenticateSession(req, res, next) {
  try {
    const token = req.cookies?.session;

    if (!token || typeof token !== 'string') {
      return res.status(401).json({
        error: 'UNAUTHENTICATED',
        message: 'Autenticação necessária.'
      });
    }

    const tokenHash = hashSessionToken(token);

    const result = await pool.query(
      `
      SELECT
        s.user_id,
        s.tenant_id,
        u.email,
        u.is_active AS user_active,
        t.is_active AS tenant_active,
        t.subscription_status

      FROM user_sessions s

      INNER JOIN users u
        ON u.id = s.user_id

      INNER JOIN tenants t
        ON t.id = s.tenant_id

      WHERE s.token_hash = $1
        AND s.expires_at > NOW()
        AND u.is_active = TRUE
        AND t.is_active = TRUE
        AND t.subscription_status = 'active'

      LIMIT 1
      `,
      [tokenHash]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        error: 'UNAUTHENTICATED',
        message: 'Sessão inválida ou expirada.'
      });
    }

    const session = result.rows[0];

    /*
     * O tenantId utilizado pelo restante da aplicação
     * vem da sessão autenticada, nunca do request.
     */
    req.auth = {
      userId: session.user_id,
      tenantId: session.tenant_id,
      email: session.email
    };

    return next();

  } catch (error) {
    console.error('Session validation error:', error);

    return res.status(500).json({
      error: 'INTERNAL_ERROR',
      message: 'Não foi possível validar a sessão.'
    });
  }
}


/*
 * Exemplo de endpoint protegido.
 *
 * Observe que não existe:
 *
 * req.query.tenantId
 * req.body.tenantId
 * req.params.tenantId
 *
 * O tenant vem exclusivamente da sessão.
 */
app.get('/api/me', authenticateSession, async (req, res) => {
  const result = await pool.query(
    `
    SELECT
      id,
      email,
      name
    FROM users
    WHERE id = $1
      AND tenant_id = $2
      AND is_active = TRUE
    `,
    [
      req.auth.userId,
      req.auth.tenantId
    ]
  );

  if (result.rowCount === 0) {
    return res.status(401).json({
      error: 'UNAUTHENTICATED',
      message: 'Usuário não encontrado.'
    });
  }

  return res.json({
    user: result.rows[0],
    tenantId: req.auth.tenantId
  });
});


/*
 * Logout.
 *
 * Revoga a sessão no servidor e remove o cookie.
 */
app.post('/api/auth/logout', authenticateSession, async (req, res) => {
  const token = req.cookies.session;
  const tokenHash = hashSessionToken(token);

  await pool.query(
    `
    DELETE FROM user_sessions
    WHERE token_hash = $1
      AND user_id = $2
      AND tenant_id = $3
    `,
    [
      tokenHash,
      req.auth.userId,
      req.auth.tenantId
    ]
  );

  res.clearCookie('session', {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/'
  });

  return res.status(204).send();
});


/*
 * Inicialização.
 */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
