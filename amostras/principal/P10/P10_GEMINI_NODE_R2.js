// routes/userRoutes.js
import { Router } from 'express';
import bcrypt from 'bcrypt';
import { z } from 'zod';
import { db } from '../config/database.js'; // Conexão com banco relacional (ex: PostgreSQL / Knex / Prisma)

const router = Router();

// Schema de validação dos dados de entrada
const createUserSchema = z.object({
  name: z.string().trim().min(2, 'O nome deve ter no mínimo 2 caracteres').max(100),
  email: z.string().trim().toLowerCase().email('E-mail inválido'),
  password: z.string().min(8, 'A senha deve conter pelo menos 8 caracteres')
});

router.post('/users', async (req, res, next) => {
  try {
    // 1. Extração do contexto multi-tenant
    // O tenant_id é injetado por um middleware prévio de autenticação/resolução de tenant (ex: via JWT ou subdomínio)
    const tenantId = req.tenant?.id;
    if (!tenantId) {
      return res.status(403).json({
        error: 'Acesso negado: contexto de empresa/locatário não identificado.'
      });
    }

    // 2. Validação do payload
    const parsedData = createUserSchema.safeParse(req.body);
    if (!parsedData.success) {
      return res.status(400).json({
        error: 'Dados inválidos.',
        details: parsedData.error.issues.map(issue => ({
          field: issue.path.join('.'),
          message: issue.message
        }))
      });
    }

    const { name, email, password } = parsedData.data;

    // 3. Verificação de conflito de e-mail no mesmo tenant
    const existingUser = await db('users')
      .where({ tenant_id: tenantId, email })
      .first();

    if (existingUser) {
      return res.status(409).json({
        error: 'Já existe um usuário cadastrado com este e-mail nesta empresa.'
      });
    }

    // 4. Hash seguro da senha
    const SALT_ROUNDS = 12;
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    // 5. Persistência com vínculo obrigatório de tenant
    const [newUser] = await db('users')
      .insert({
        tenant_id: tenantId,
        name,
        email,
        password_hash: passwordHash,
        role: 'MEMBER',
        created_at: new Date(),
        updated_at: new Date()
      })
      .returning(['id', 'tenant_id', 'name', 'email', 'role', 'created_at']);

    // 6. Resposta sem expor dados sensíveis
    return res.status(201).json({
      data: newUser
    });

  } catch (error) {
    // Encaminha para o middleware global de tratamento de erros
    next(error);
  }
});

export default router;

// middlewares/tenantContext.js
export function resolveTenant(req, res, next) {
  // Exemplo via JWT decodificado no header Authorization
  const userTokenData = req.auth; // Preenchido por express-jwt ou similar

  if (!userTokenData?.tenant_id) {
    return res.status(401).json({ error: 'Token inválido ou sem tenant associado.' });
  }

  req.tenant = {
    id: userTokenData.tenant_id
  };

  next();
}