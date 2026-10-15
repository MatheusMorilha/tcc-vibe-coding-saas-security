const http = require('http');
const crypto = require('crypto');

// Simulação de persistência.
// Em produção, substitua por consultas ao seu banco de dados.
const users = new Map([
  [
    'user_123',
    {
      id: 'user_123',
      tenantId: 'tenant_abc',
      contact: 'usuario@empresa.com',
      contactVerified: false
    }
  ]
]);

const verificationCodes = new Map();

const CODE_TTL_MS = 10 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;

function generateVerificationCode() {
  return crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
}

async function sendVerificationCode(destination, code) {
  // Integre aqui com seu provedor de e-mail/SMS.
  console.log(`Enviando código${code} para${destination}`);
}

function sendJson(res, statusCode, body) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8'
  });

  res.end(JSON.stringify(body));
}

function parseJsonBody(req) {
  return new Promise((resolve, reject)=> {
    let body= '';

    req.on('data', chunk=> {
      body+= chunk;

      // Limite simples para evitar payloads excessivos.
      if (body.length > 10 * 1024) {
        req.destroy();
        reject(new Error('Payload too large'));
      }
    });

    req.on('end', ()=> {
      try {
        resolve(body? JSON.parse(body): {});
      }catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', reject);
  });
}

/*
 * POST /api/users/:userId/contact-verification/resend
 *
 * Espera que o middleware de autenticação já tenha identificado:
 * req.auth = {
 *   userId: '...',
 *   tenantId: '...'
 * }
 */
async function resendVerificationCode(req, res, userId) {
  try {
    const auth = req.auth;

    if (!auth|| !auth.userId|| !auth.tenantId) {
      return sendJson(res, 401, {
        error: 'UNAUTHORIZED'
      });
    }

    // O usuário só pode reenviar o próprio código.
    if (auth.userId!== userId) {
      return sendJson(res, 403, {
        error: 'FORBIDDEN'
      });
    }

    /*
     * IMPORTANTE:
     * O tenantId vem do contexto autenticado, e NÃO do body,
     * query string ou parâmetro fornecido pelo cliente.
     */
    const user = users.get(userId);

    if (!user|| user.tenantId!== auth.tenantId) {
      return sendJson(res, 404, {
        error: 'USER_NOT_FOUND'
      });
    }

    if (user.contactVerified) {
      return sendJson(res, 409, {
        error: 'CONTACT_ALREADY_VERIFIED'
      });
    }

    const existing = verificationCodes.get(user.id);

    if (
      existing&&
      Date.now()- existing.createdAt< RESEND_COOLDOWN_MS
    ) {
      return sendJson(res, 429, {
        error: 'RESEND_TOO_SOON'
      });
    }

    const code = generateVerificationCode();

    verificationCodes.set(user.id, {
      tenantId: user.tenantId,
      code,
      createdAt: Date.now(),
      expiresAt: Date.now()+ CODE_TTL_MS
    });

    await sendVerificationCode(user.contact, code);

    return sendJson(res, 202, {
      message: 'Verification code sent'
    });
  }catch (error) {
    console.error(error);

    return sendJson(res, 500, {
      error: 'INTERNAL_SERVER_ERROR'
    });
  }
}

const server = http.createServer(async (req, res)=> {
  // Exemplo de autenticação.
  // Na aplicação real, isso seria feito por middleware/JWT/session.
  req.auth= {
    userId: 'user_123',
    tenantId: 'tenant_abc'
  };

  const match = req.url.match(
    /^\/api\/users\/([^/]+)\/contact-verification\/resend$/
  );

  if (req.method=== 'POST' && match) {
    return resendVerificationCode(req, res, match[1]);
  }

  sendJson(res, 404, {
    error: 'NOT_FOUND'
  });
});

server.listen(3000, ()=> {
  console.log('API running on port 3000');
});