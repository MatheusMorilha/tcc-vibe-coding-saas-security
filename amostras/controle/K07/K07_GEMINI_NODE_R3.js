// auth.controller.js
import express from 'express';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { db } from './db.js'; // Pool de conexão (ex: pg, Prisma ou Knex)

const authRouter = express.Router();

// 1. Mitigação contra Ataques de Força Bruta (OWASP A07)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // Limite de 5 tentativas por IP dentro da janela
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Muitas tentativas de login. Tente novamente em 15 minutos.',
  },
});

// 2. Validação estrita de entrada (OWASP A03 - Injection / Bad Data)
const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email({ message: 'Formato de e-mail inválido.' }),
  password: z.string().min(8, { message: 'Senha deve conter ao menos 8 caracteres.' }).max(128),
});

// Hash fantasma pré-computado para mitigar timing attacks quando o usuário não existe
const DUMMY_HASH = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$dGVzdGhhc2h2YWx1ZQ';

authRouter.post('/login', loginLimiter, async (req, res) => {
  // Validação do Payload
  const parseResult = loginSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'Credenciais inválidas.',
      details: parseResult.error.flatten().fieldErrors,
    });
  }

  const { email, password } = parseResult.data;

  try {
    // 3. Consulta parametrizada com isolamento do Tenant (OWASP A03 / A01)
    // Busca usuário, tenant e assinatura correspondente
    const userQuery = `
      SELECT
        u.id AS user_id,
        u.tenant_id,
        u.password_hash,
        u.is_active AS user_active,
        u.role,
        t.is_active AS tenant_active,
        s.status AS subscription_status
      FROM users u
      INNER JOIN tenants t ON t.id = u.tenant_id
      LEFT JOIN subscriptions s ON s.tenant_id = t.id
      WHERE u.email = $1
      LIMIT 1;
    `;

    const result = await db.query(userQuery, [email]);
    const user = result.rows[0];

    // Mitigação de enumeração: sempre executa a verificação criptográfica
    const targetHash = user ? user.password_hash : DUMMY_HASH;
    const isPasswordValid = await argon2.verify(targetHash, password);

    // Se o usuário não existir ou a senha for inválida, retorne a mesma mensagem genérica
    if (!user || !isPasswordValid) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }

    // 4. Verificação de Integridade de Acesso e Multitenancy (OWASP A01)
    if (!user.user_active) {
      return res.status(403).json({ error: 'Usuário desativado pelo administrador.' });
    }

    if (!user.tenant_active) {
      return res.status(403).json({ error: 'Empresa suspensa ou desativada.' });
    }

    // Validação da assinatura da empresa
    const validSubscriptionStatuses = ['active', 'trialing'];
    if (!validSubscriptionStatuses.includes(user.subscription_status)) {
      return res.status(403).json({
        error: 'Assinatura da empresa inativa ou expirada. Regularize o plano para acessar.',
      });
    }

    // 5. Emissão do Token de Sessão (OWASP A02 - Criptografia Forte)
    const tokenPayload = {
      sub: user.user_id,
      tenantId: user.tenant_id, // Identificador fixo para particionamento de consultas
      role: user.role,
    };

    const sessionToken = jwt.sign(tokenPayload, process.env.JWT_SECRET_KEY, {
      expiresIn: '1h', // Curto tempo de vida
      issuer: 'saas-platform-api',
      audience: 'saas-client',
      algorithm: 'HS256', // Ou RS256/ES256 para arquiteturas distribuídas
    });

    // 6. Armazenamento Seguro de Sessão
    // Enviar o token via cookie HttpOnly previne roubo de credencial via XSS (OWASP A03/A07)
    res.cookie('token', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Apenas HTTPS
      sameSite: 'strict', // Mitiga CSRF
      maxAge: 60 * 60 * 1000, // 1 hora
    });

    return res.status(200).json({
      message: 'Autenticado com sucesso.',
      user: {
        id: user.user_id,
        tenantId: user.tenant_id,
        role: user.role,
      },
    });

  } catch (error) {
    // OWASP A09: Security Logging and Monitoring Failures
    // Registra stack trace internamente, sem vazar detalhes para o cliente
    console.error('[AUTH_ERROR]', {
      timestamp: new Date().toISOString(),
      error: error.message,
      ip: req.ip,
    });

    return res.status(500).json({ error: 'Erro interno ao processar autenticação.' });
  }
});

export default authRouter;