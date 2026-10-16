import express from 'express';
import bcrypt from 'bcrypt';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import rateLimit from 'express-rate-limit';

const router = express.Router();
const prisma = new PrismaClient();

// 1. Proteção contra Brute Force e DoS (OWASP A04:2021 - Unsecure Design)
const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10, // Máximo de 10 tentativas por IP por janela
  message: { error: 'Muitas tentativas de cadastro a partir deste IP. Tente novamente mais tarde.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// 2. Schema de validação com Zod (OWASP A03:2021 - Injection & Sanitization)
const registerUserSchema = z.object({
  tenantId: z.string().uuid({ message: 'ID do locatário inválido.' }),
  name: z
    .string()
    .trim()
    .min(2, { message: 'O nome deve ter no mínimo 2 caracteres.' })
    .max(100, { message: 'O nome deve ter no máximo 100 caracteres.' }),
  email: z
    .string()
    .trim()
    .toLowerCase()
    .email({ message: 'Formato de e-mail inválido.' })
    .max(255),
  password: z
    .string()
    .min(12, { message: 'A senha deve conter no mínimo 12 caracteres.' })
    .max(128)
    .regex(/[A-Z]/, { message: 'A senha deve conter pelo menos uma letra maiúscula.' })
    .regex(/[a-z]/, { message: 'A senha deve conter pelo menos uma letra minúscula.' })
    .regex(/[0-9]/, { message: 'A senha deve conter pelo menos um número.' })
    .regex(/[^A-Za-z0-9]/, { message: 'A senha deve conter pelo menos um caractere especial.' }),
});

router.post('/users', signupLimiter, async (req, res) => {
  try {
    // Validação e sanitização dos dados de entrada
    const validatedData = registerUserSchema.parse(req.body);
    const { tenantId, name, email, password } = validatedData;

    // 3. Verificação de Tenant Ativo e Existente (OWASP A01:2021 - Broken Access Control)
    const tenant = await prisma.tenant.findUnique({
      where: { id: tenantId },
      select: { id: true, status: true },
    });

    if (!tenant || tenant.status !== 'ACTIVE') {
      return res.status(400).json({ error: 'Locatário (empresa) inválido ou inativo.' });
    }

    // 4. Verificação de Duplicidade de E-mail por Tenant
    const existingUser = await prisma.user.findFirst({
      where: {
        tenantId,
        email,
      },
      select: { id: true },
    });

    if (existingUser) {
      return res.status(409).json({ error: 'O e-mail informado já está cadastrado para esta empresa.' });
    }

    // 5. Criptografia Forte de Senha (OWASP A02:2021 - Cryptographic Failures)
    // Custo de Hashing (Salt Rounds) = 12 para garantir forte resistência a brute-force
    const hashedPassword = await bcrypt.hash(password, 12);

    // 6. Persistência Isolada com Tenant Scope (OWASP A01:2021)
    const newUser = await prisma.user.create({
      data: {
        tenantId,
        name,
        email,
        password: hashedPassword,
        role: 'MEMBER', // Papel padrão com menor privilégio (OWASP Principal of Least Privilege)
      },
      // Exclui a senha do retorno diretamente na consulta ao banco
      select: {
        id: true,
        tenantId: true,
        name: true,
        email: true,
        role: true,
        createdAt: true,
      },
    });

    // Retorno do usuário criado sem vazamento de credenciais
    return res.status(201).json({
      message: 'Usuário cadastrado com sucesso.',
      user: newUser,
    });

  } catch (error) {
    // Trata erros de validação da Zod
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Erro de validação nos dados fornecidos.',
        details: error.errors.map((err) => ({ field: err.path.join('.'), message: err.message })),
      });
    }

    // 7. Tratamento Genérico de Erros e Logging Seguro (OWASP A09:2021 - Security Logging Failure)
    // Registra o erro internamente sem expor detalhes técnicos/stack trace ao cliente
    console.error('[SIGNUP_ERROR]', {
      timestamp: new Date().toISOString(),
      error: error.message,
    });

    return res.status(500).json({ error: 'Ocorreu um erro interno ao processar o cadastro.' });
  }
});

export default router;