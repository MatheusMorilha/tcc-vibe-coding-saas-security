const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const router = express.Router();
const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || 'sua_chave_secreta_super_segura';
const JWT_EXPIRES_IN = '8h';

/**
 * POST /api/v1/auth/login
 * Realiza autenticação do usuário e retorna JWT de sessão com contexto multi-tenant.
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Validação simples de entrada
    if (!email || !password) {
      return res.status(400).json({
        error: 'E-mail e senha são obrigatórios.'
      });
    }

    // 2. Busca o usuário e inclui a empresa (tenant) associada
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase().trim() },
      include: {
        company: true
      }
    });

    // 3. Validação de credenciais (evita enumerar usuários usando mensagem genérica)
    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    // 4. Validação de segurança do usuário
    if (!user.isActive) {
      return res.status(403).json({ error: 'Usuário inativo. Entre em contato com o administrador.' });
    }

    // 5. Validação da Empresa e Assinatura SaaS (Multi-tenancy)
    const company = user.company;
    if (!company || !company.isActive) {
      return res.status(403).json({ error: 'Acesso negado: Empresa inativa ou desativada.' });
    }

    if (company.subscriptionStatus !== 'ACTIVE' && company.subscriptionStatus !== 'TRIAL') {
      return res.status(402).json({
        error: 'Pagamento necessário: A assinatura da empresa está suspensa ou expirada.'
      });
    }

    // 6. Geração do Payload do Token JWT
    const payload = {
      sub: user.id,               // ID do usuário (subject)
      email: user.email,
      role: user.role,            // Nível de permissão (ex: ADMIN, USER)
      companyId: company.id,      // Tenant ID chave para filtro de dados
      companySlug: company.slug
    };

    // 7. Assinatura do Token
    const token = jwt.sign(payload, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN
    });

    // 8. Resposta de sucesso
    return res.status(200).json({
      message: 'Autenticação realizada com sucesso.',
      accessToken: token,
      tokenType: 'Bearer',
      expiresIn: JWT_EXPIRES_IN,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        company: {
          id: company.id,
          name: company.name,
          slug: company.slug
        }
      }
    });

  } catch (error) {
    console.error('[AUTH_LOGIN_ERROR]:', error);
    return res.status(500).json({
      error: 'Ocorreu um erro interno ao processar a autenticação.'
    });
  }
});

module.exports = router;