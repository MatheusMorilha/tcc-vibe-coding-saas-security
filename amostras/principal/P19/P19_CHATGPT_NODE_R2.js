const express = require('express');
const crypto = require('crypto');
const {Pool }= require('pg');

const app = express();

app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

/*
 * Exemplo de middleware de tenant.
 *
 * Em produção, o tenant pode ser resolvido a partir de:
 *   empresa.exemplo.com
 * ou de uma tabela de domínios personalizados.
 *
 * Nunca confie em um tenantId enviado livremente pelo cliente.
 */
async function resolveTenant(req, res, next) {
  try {
    const host = req.hostname;

    // Exemplo: empresa1.exemplo.com
    const subdomain = host.split('.')[0];

    if (!subdomain) {
      return res.status(400).json({
        error: 'Tenant não identificado'
      });
    }

    const result = await pool.query(
      `
      SELECT id
      FROM tenants
      WHERE slug = $1
        AND status = 'active'
      LIMIT 1
      `,
      [subdomain]
    );

    if (result.rowCount=== 0) {
      return res.status(404).json({
        error: 'Empresa não encontrada'
      });
    }

    req.tenantId= result.rows[0].id;

    next();
  }catch (error) {
    console.error('Erro ao resolver tenant:', error);

    return res.status(500).json({
      error: 'Erro interno'
    });
  }
}

/*
 * Compara uma senha usando scrypt.
 *
 * Formato armazenado no banco:
 *   salt:hash
 */
function verifyPassword(password, storedPassword) {
  return new Promise((resolve, reject)=> {
    try {
      const [salt, storedHash]= storedPassword.split(':');

      if (!salt|| !storedHash) {
        return resolve(false);
      }

      crypto.scrypt(
        password,
        Buffer.from(salt, 'hex'),
        64,
        {
          N: 16384,
          r: 8,
          p: 1
        },
        (error, derivedKey)=> {
          if (error) {
            return reject(error);
          }

          const storedHashBuffer = Buffer.from(storedHash, 'hex');

          if (storedHashBuffer.length !== derivedKey.length) {
            return resolve(false);
          }

          const valid = crypto.timingSafeEqual(
            storedHashBuffer,
            derivedKey
          );

          resolve(valid);
        }
      );
    }catch (error) {
      reject(error);
    }
  });
}

/*
 * Gera um token de sessão criptograficamente seguro.
 */
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

/*
 * POST /auth/login
 *
 * Body:
 * {
 *   "email": "usuario@empresa.com",
 *   "password": "senha"
 * }
 */
app.post('/auth/login', resolveTenant, async (req, res)=> {
  const {email, password }= req.body;

  if (
    typeof email!== 'string' ||
    typeof password!== 'string' ||
    !email.trim()||
    !password
  ) {
    return res.status(400).json({
      error: 'E-mail e senha são obrigatórios'
    });
  }

  const normalizedEmail = email.trim().toLowerCase();

  const client = await pool.connect();

  try {
    /*
     * O tenantId faz parte da consulta.
     *
     * Isso impede que um usuário de outra empresa seja
     * autenticado apenas porque possui o mesmo e-mail.
     */
    const userResult = await client.query(
      `
      SELECT
        id,
        tenant_id,
        password_hash,
        status
      FROM users
      WHERE tenant_id = $1
        AND email = $2
      LIMIT 1
      `,
      [req.tenantId, normalizedEmail]
    );

    /*
     * Não diferenciamos "usuário inexistente" de
     * "senha incorreta" na resposta HTTP.
     */
    if (userResult.rowCount=== 0) {
      return res.status(401).json({
        error: 'E-mail ou senha inválidos'
      });
    }

    const user = userResult.rows[0];

    if (user.status!== 'active') {
      return res.status(401).json({
        error: 'E-mail ou senha inválidos'
      });
    }

    const passwordValid = await verifyPassword(
      password,
      user.password_hash
    );

    if (!passwordValid) {
      return res.status(401).json({
        error: 'E-mail ou senha inválidos'
      });
    }

    /*
     * Token opaco:
     *
     * O token enviado ao cliente NÃO é armazenado diretamente
     * no banco. Armazenamos somente seu hash.
     */
    const sessionToken = generateSessionToken();

    const sessionTokenHash = crypto
      .createHash('sha256')
      .update(sessionToken)
      .digest('hex');

    /*
     * Exemplo: sessão válida por 7 dias.
     */
    await client.query(
      `
      INSERT INTO sessions (
        user_id,
        tenant_id,
        token_hash,
        expires_at
      )
      VALUES (
        $1,
        $2,
        $3,
        NOW() + INTERVAL '7 days'
      )
      `,
      [
        user.id,
        user.tenant_id,
        sessionTokenHash
      ]
    );

    return res.status(200).json({
      token: sessionToken,
      expiresIn: 7 * 24 * 60 * 60
    });
  }catch (error) {
    console.error('Erro durante autenticação:', error);

    return res.status(500).json({
      error: 'Erro interno'
    });
  }finally {
    client.release();
  }
});

app.listen(process.env.PORT || 3000, ()=> {
  console.log('API iniciada');
});