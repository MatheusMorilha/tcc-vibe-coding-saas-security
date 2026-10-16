import express from 'express';
import { z } from 'zod';
import argon2 from 'argon2';
import { db } from '../database/connection.js'; // Exemplo de instância do banco (Prisma, Knex, Pg, etc.)

const router = express.Router();

// Schema de validação de input com Zod (OWASP A03: Injection & A04: Insecure Design)
const createUserSchema = z.object({
  name: z
    .string({ required_error: 'Nome é obrigatório.' })
    .trim()
    .min(2, 'O nome deve ter no mínimo 2 caracteres.')
    .max(100, 'O nome deve ter no máximo 100 caracteres.'),
  email: z
    .string({ required_error: 'E-mail é obrigatório.' })
    .trim()
    .email('Formato de e-mail inválido.')
    .toLowerCase(),
  password: z
    .string({ required_error: 'Senha é obrigatória.' })
    .min(12, 'A senha deve conter no mínimo 12 caracteres.') // Recomendação OWASP
    .max(128, 'A senha deve conter no máximo 128 caracteres.')
    .refine((val) => /[A-Z]/.test(val), { message: 'A senha deve conter ao menos uma letra maiúscula.' })
    .refine((val) => /[a-z]/.test(val), { message: 'A senha deve conter ao menos uma letra minúscula.' })
    .refine((val) => /[0-9]/.test(val), { message: 'A senha deve conter ao menos um número.' })
    .refine((val) => /[^A-Za-z0-9]/.test(val), { message: 'A senha deve conter ao menos um caractere especial.' })
});

/**
 * Middleware de autenticação/contexto esperado:
 * O middleware previo valida o Token JWT e injeta `req.tenantId` e `req.user`.
 */
router.post('/users', async (req, res, next) => {
  try {
    // 1. Garantir contexto do Tenant (OWASP A01: Broken Access Control)
    const tenantId = req.tenantId;
    if (!tenantId) {
      return res.status(403).json({
        error: 'Acesso negado. Contexto de organização não identificado.'
      });
    }

    // 2. Validação e sanitização rigorosa do body (OWASP A03: Injection)
    const validation = createUserSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({
        error: 'Dados de entrada inválidos.',
        details: validation.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message
        }))
      });
    }

    const { name, email, password } = validation.data;

    // 3. Verificação de duplicidade dentro do escopo do Tenant / Plataforma
    const existingUser = await db('users')
      .where({ email, tenant_id: tenantId })
      .first();

    if (existingUser) {
      return res.status(409).json({
        error: 'Já existe um usuário cadastrado com este e-mail.'
      });
    }

    // 4. Hash seguro da senha usando Argon2id (OWASP A02: Cryptographic Failures)
    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16, // 64 MB
      timeCost: 3,         // 3 iterações
      parallelism: 1
    });

    // 5. Persistência isolada com vínculo obrigatório do tenant_id (Multi-tenancy)
    const [newUser] = await db('users')
      .insert({
        tenant_id: tenantId,
        name,
        email,
        password_hash: passwordHash,
        status: 'ACTIVE',
        created_at: new Date()
      })
      .returning(['id', 'tenant_id', 'name', 'email', 'status', 'created_at']);

    // 6. Retorno dos dados higienizados (Sem expor o hash de senha)
    return res.status(201).json({
      message: 'Usuário cadastrado com sucesso.',
      data: newUser
    });

  } catch (error) {
    // 7. Mapeamento e Logging seguro de erros (OWASP A09: Security Logging & Monitoring)
    // Log interno detalhado para auditoria (nunca exposto ao cliente)
    console.error('[CreateUserError]:', {
      tenantId: req.tenantId,
      message: error.message,
      timestamp: new Date().toISOString()
    });

    return res.status(500).json({
      error: 'Ocorreu um erro interno ao processar a solicitação.'
    });
  }
});

export default router;