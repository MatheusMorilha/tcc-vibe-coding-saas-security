import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import rateLimit from 'express-rate-limit';

const router = express.Router();

// -----------------------------------------------------------------------------
// 1. Mitigação contra Força Bruta e DoS (OWASP A07: Identification & Auth Failures)
// -----------------------------------------------------------------------------
export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // Janela de 15 minutos
  max: 5, // Limite de 5 tentativas por IP dentro da janela
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Muitas tentativas de login a partir deste endereço. Tente novamente mais tarde.'
  }
});

// -----------------------------------------------------------------------------
// 2. Validação Rigorosa de Entrada (OWASP A03: Injection)
// -----------------------------------------------------------------------------
const loginSchema = z.object({
  email: z
    .string({ required_error: 'O e-mail é obrigatório.' })
    .email('Formato de e-mail inválido.')
    .trim()
    .toLowerCase(),
  password: z
    .string({ required_error: 'A senha é obrigatória.' })
    .min(1, 'A senha não pode estar vazia.')
    .max(128, 'Senha excede o comprimento máximo permitido.') // Previne ataques de DoS via bcrypt
});

// -----------------------------------------------------------------------------
// 3. Simulação de Camada de Dados (Substituir pelo seu ORM/Query Builder seguro)
// NOTA: Sempre use consultas parametrizadas (Prepared Statements) contra SQL Injection.
// -----------------------------------------------------------------------------
async function findUserWithTenantByEmail(email){
  // Exemplo de retorno esperado da consulta parametrizada:
  // SELECT u.id, u.tenant_id, u.password_hash, u.is_active, u.role,
  //        t.subscription_status
  // FROM users u
  // JOIN tenants t ON u.tenant_id = t.id
  // WHERE u.email = $1;
  return null;
}

// -----------------------------------------------------------------------------
// 4. Rota de Autenticação (POST /api/v1/auth/login)
// -----------------------------------------------------------------------------
router.post('/login', loginRateLimiter, async (req, res) => {
  // Resposta genérica para evitar enumeração de contas (OWASP A07)
  const invalidCredentialsResponse = () =>
    res.status(401).json({
      status: 'error',
      message: 'Credenciais inválidas.'
    });

  try {
    // Validação de formato da payload
    const parsedData = loginSchema.safeParse(req.body);
    if (!parsedData.success) {
      return res.status(400).json({
        status: 'error',
        message: 'Parâmetros de requisição inválidos.',
        errors: parsedData.error.issues.map(issue => ({
          field: issue.path.join('.'),
          message: issue.message
        }))
      });
    }

    const { email, password } = parsedData.data;

    // Busca usuário e estado do Tenant
    const user = await findUserWithTenantByEmail(email);

    // Timing-attack prevention: se o usuário não existir, executa um compare falso
    if (!user) {
      const dummyHash = '$2b$12$e8rGgX1oAOmkM.u0FvhKyeq6hQj0j0W0vA3qE9NlK8uM9dMhU8O2e';
      await bcrypt.compare(password, dummyHash);
      return invalidCredentialsResponse();
    }

    // Validação criptográfica da senha (OWASP A02: Cryptographic Failures)
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return invalidCredentialsResponse();
    }

    // Verificação de status do usuário
    if (!user.isActive) {
      return res.status(403).json({
        status: 'error',
        message: 'Acesso negado: Conta inativa.'
      });
    }

    // Validação de isolamento do Tenant e plano ativo (OWASP A01: Broken Access Control)
    if (user.tenantSubscriptionStatus !== 'ACTIVE') {
      return res.status(402).json({
        status: 'error',
        message: 'Acesso suspenso: A assinatura da empresa está inativa ou cancelada.'
      });
    }

    // -------------------------------------------------------------------------
    // 5. Emissão do Token de Sessão JWT (OWASP A02 & A07)
    // -------------------------------------------------------------------------
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret || jwtSecret.length < 32) {
      throw new Error('CONFIG_ERROR: JWT_SECRET não configurado ou muito curto.');
    }

    // Payload mínima: apenas os identificadores necessários para autorização
    // NUNCA incluir senhas, hashes ou dados PII desnecessários no JWT.
    const tokenPayload = {
      sub: user.id,
      tenantId: user.tenantId, // Vínculo explícito do contexto multi-tenant
      role: user.role
    };

    const token = jwt.sign(tokenPayload, jwtSecret, {
      algorithm: 'HS256',
      expiresIn: '1h',
      issuer: 'saas-core-api',
      audience: 'saas-web-client'
    });

    // Envia o token via cookie HttpOnly/Secure (protege contra XSS - OWASP A03)
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000 // 1 hora
    });

    // Retorna dados públicos da sessão
    return res.status(200).json({
      status: 'success',
      message: 'Autenticação realizada com sucesso.',
      data: {
        userId: user.id,
        tenantId: user.tenantId,
        role: user.role
      }
    });

  } catch (error) {
    // Log interno detalhado sem expor stack trace ao cliente (OWASP A05: Security Misconfiguration)
    console.error('[AuthService Error]:', error);

    return res.status(500).json({
      status: 'error',
      message: 'Ocorreu um erro interno durante a autenticação.'
    });
  }
});

export default router;