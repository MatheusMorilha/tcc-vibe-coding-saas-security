import express from 'express';
import bcrypt from 'bcrypt';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const router = express.Router();

// BCRYPT COST FACTOR (Mínimo recomendado OWASP: 12)
const BCRYPT_SALT_ROUNDS = 12;

// Schema de validação estrita dos dados de entrada (Zod)
const createUserSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, { message: 'O nome deve ter pelo menos 2 caracteres.' })
    .max(100, { message: 'O nome não pode exceder 100 caracteres.' }),
  email: z
    .string()
    .trim()
    .lowercase()
    .email({ message: 'Formato de e-mail inválido.' }),
  password: z
    .string()
    .min(10, { message: 'A senha deve ter no mínimo 10 caracteres.' })
    .max(128, { message: 'A senha não pode exceder 128 caracteres.' })
    .regex(/[A-Z]/, { message: 'A senha deve conter ao menos uma letra maiúscula.' })
    .regex(/[a-z]/, { message: 'A senha deve conter ao menos uma letra minúscula.' })
    .regex(/[0-9]/, { message: 'A senha deve conter ao menos um número.' })
    .regex(/[^A-Za-z0-9]/, { message: 'A senha deve conter ao menos um caractere especial.' }),
});

/**
 * POST /api/v1/users
 * Cadastro de usuário pertencente ao Tenant atual.
 * Nota: Assume que o middleware de contexto tenant (ex: via token JWT) definiu `req.tenantId`.
 */
router.post('/users', async (req, res) => {
  try {
    // 1. Verificação de Contexto Multilocatário (OWASP A01: Broken Access Control)
    const tenantId = req.tenantId || req.headers['x-tenant-id'];

    if (!tenantId) {
      return res.status(400).json({
        error: 'Identificador do locatário (tenantId) ausente no contexto da requisição.',
      });
    }

    // 2. Validação e Sanitização do Input (OWASP A03/A04)
    const validationResult = createUserSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(422).json({
        error: 'Dados de entrada inválidos.',
        details: validationResult.error.flatten().fieldErrors,
      });
    }

    const { name, email, password } = validationResult.data;

    // 3. Verificação de existência da empresa/tenant
    const tenantExists = await prisma.tenant.findUnique({
      where: { id: tenantId },
    });

    if (!tenantExists) {
      return res.status(404).json({ error: 'Empresa contratante não encontrada ou inativa.' });
    }

    // 4. Verificação de duplicação de usuário no mesmo tenant
    const existingUser = await prisma.user.findUnique({
      where: {
        tenantId_email: {
          tenantId,
          email,
        },
      },
    });

    if (existingUser) {
      return res.status(409).json({
        error: 'Conflito: Já existe um usuário cadastrado com este e-mail para esta empresa.',
      });
    }

    // 5. Hash de Senha Seguro (OWASP A02: Cryptographic Failures)
    const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

    // 6. Persistência Isolada por Tenant
    const newUser = await prisma.user.create({
      data: {
        tenantId,
        name,
        email,
        password: hashedPassword,
      },
      select: {
        id: true,
        tenantId: true,
        name: true,
        email: true,
        role: true,
        createdAt: true,
        // O campo 'password' é OMITIDO explicitamente da seleção
      },
    });

    // 7. Resposta
    return res.status(201).json({
      message: 'Usuário cadastrado com sucesso.',
      data: newUser,
    });
  } catch (error) {
    // Evita expor detalhes de infraestrutura ou stack traces no erro HTTP
    console.error('[CreateUser Error]:', error);
    return res.status(500).json({
      error: 'Erro interno no servidor ao processar a solicitação.',
    });
  }
});

export default router;