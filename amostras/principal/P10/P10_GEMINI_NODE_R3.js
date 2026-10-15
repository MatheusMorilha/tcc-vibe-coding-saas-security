import express from 'express';
import bcrypt from 'bcryptjs';
import { PrismaClient } from '@prisma/client';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * Middleware genérico para extrair e validar o tenant do contexto da requisição
 * (geralmente injetado via JWT autenticado ou Header X-Tenant-ID).
 */
function extractTenantContext(req, res, next){
  // Em uma rota autenticada por um admin da empresa, o tenantId vem do token JWT.
  // Em fluxos de convite/autocadastro, pode vir via header ou parâmetro de rota.
  const tenantId = req.headers['x-tenant-id'] || req.user?.tenantId;

  if (!tenantId) {
    return res.status(400).json({
      error: 'Tenant context is missing. O ID da empresa cliente é obrigatório.',
    });
  }

  req.tenantId = tenantId;
  next();
}

/**
 * POST /api/users
 * Cadastra um novo usuário vinculado ao Tenant ativo.
 */
router.post('/users', extractTenantContext, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const { tenantId } = req;

    // 1. Validação básica de entrada
    if (!name || !email || !password) {
      return res.status(400).json({
        error: 'Campos obrigatórios ausentes: name, email e password.',
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: 'A senha deve conter no mínimo 8 caracteres.',
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // 2. Verifica se a empresa (tenant) existe e está com assinatura ativa
    const tenant = await prisma.tenant.findUnique({
      where: { id: tenantId },
    });

    if (!tenant) {
      return res.status(404).json({ error: 'Empresa cliente não encontrada.' });
    }

    if (tenant.status !== 'ACTIVE') {
      return res.status(403).json({
        error: 'Acesso negado: a assinatura desta empresa está inativa ou cancelada.',
      });
    }

    // 3. Verifica se o e-mail já está cadastrado para este mesmo tenant
    const existingUser = await prisma.user.findFirst({
      where: {
        email: normalizedEmail,
        tenantId: tenantId,
      },
    });

    if (existingUser) {
      return res.status(409).json({
        error: 'Já existe um usuário cadastrado com este e-mail nesta empresa.',
      });
    }

    // 4. Criptografia segura da senha
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // 5. Persistência isolada por Tenant
    const newUser = await prisma.user.create({
      data: {
        name: name.trim(),
        email: normalizedEmail,
        passwordHash,
        tenantId,
      },
      select: {
        id: true,
        name: true,
        email: true,
        tenantId: true,
        createdAt: true,
      },
    });

    // 6. Retorno dos dados criados (sem expor a senha)
    return res.status(201).json({
      message: 'Usuário cadastrado com sucesso.',
      data: newUser,
    });

  } catch (error) {
    console.error('Erro ao cadastrar usuário:', error);
    return res.status(500).json({
      error: 'Erro interno do servidor ao processar o cadastro.',
    });
  }
});

export default router;