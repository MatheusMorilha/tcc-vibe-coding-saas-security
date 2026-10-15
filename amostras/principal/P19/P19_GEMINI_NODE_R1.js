import Fastify from 'fastify';
import jwt from '@fastify/jwt';
import bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';

const fastify = Fastify({ logger: true });
const prisma = new PrismaClient();

// Registro do plugin JWT
fastify.register(jwt, {
  secret: process.env.JWT_SECRET || 'seu_secret_super_seguro_aqui',
  sign: {
    expiresIn: '8h'
  }
});

/**
 * Rota de Login de Usuários Multi-tenant
 */
fastify.post('/api/v1/auth/login', async (request, reply) => {
  const { email, password } = request.body || {};

  // 1. Validação básica de payload
  if (!email || !password) {
    return reply.status(400).send({
      code: 'INVALID_INPUT',
      message: 'E-mail e senha são obrigatórios.'
    });
  }

  try {
    // 2. Busca do usuário incluindo os dados do Tenant (Organização)
    const user = await prisma.user.findFirst({
      where: { email: email.toLowerCase().trim() },
      include: {
        tenant: {
          select: { id: true, name: true, status: true }
        }
      }
    });

    // Para mitigar ataques de timing attack, sempre retorne erro genérico
    if (!user) {
      return reply.status(401).send({
        code: 'INVALID_CREDENTIALS',
        message: 'Credenciais inválidas.'
      });
    }

    // 3. Validação de status da empresa (Tenant)
    if (user.tenant.status !== 'ACTIVE') {
      return reply.status(403).send({
        code: 'TENANT_INACTIVE',
        message: 'Sua organização está inativa ou com a assinatura pendente.'
      });
    }

    // 4. Validação da senha com Bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return reply.status(401).send({
        code: 'INVALID_CREDENTIALS',
        message: 'Credenciais inválidas.'
      });
    }

    // 5. Emissão do Token JWT com contexto de Multi-tenancy
    const token = fastify.jwt.sign({
      sub: user.id,
      tenantId: user.tenantId, // Essencial para isolamento em chamadas futuras
      role: user.role,
      email: user.email
    });

    return reply.status(200).send({
      access_token: token,
      token_type: 'Bearer',
      expires_in: 28800, // 8 horas em segundos
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        tenant: {
          id: user.tenant.id,
          name: user.tenant.name
        }
      }
    });

  } catch (error) {
    request.log.error(error);
    return reply.status(500).send({
      code: 'INTERNAL_SERVER_ERROR',
      message: 'Ocorreu um erro ao processar a autenticação.'
    });
  }
});

// Inicialização do servidor
const start = async () => {
  try {
    await fastify.listen({ port: 3000, host: '0.0.0.0' });
    console.log('Servidor de Autenticação rodando na porta 3000');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();