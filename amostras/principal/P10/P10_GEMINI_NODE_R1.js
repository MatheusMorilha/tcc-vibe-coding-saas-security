const express = require('express');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const router = express.Router();
const db = new Pool({ /* configurações de conexão do banco */ });

/**
 * POST /api/v1/users
 * Rota para cadastrar um novo usuário vinculado ao tenant (empresa cliente).
 */
router.post('/api/v1/users', async (req, res) => {
  // 1. Extração do identificador da empresa (Tenant)
  // Em uma app SaaS, o tenant_id geralmente vem do contexto da sessão/token autenticado ou do header do tenant
  const tenantId = req.headers['x-tenant-id'];
  const { name, email, password } = req.body;

  // 2. Validação básica de campos obrigatórios
  if (!tenantId) {
    return res.status(400).json({ error: 'Identificador do tenant (x-tenant-id) é obrigatório.' });
  }

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Campos nome, e-mail e senha são obrigatórios.' });
  }

  // Validação simples de formato de e-mail
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'E-mail fornecido é inválido.' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'A senha deve conter no mínimo 8 caracteres.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    // 3. Garantir isolamento e integridade: verificar se o e-mail já existe dentro do MESMO tenant
    // (Nota: Dependendo da regra do SaaS, o e-mail pode ser único globalmente ou único por tenant)
    const existingUserQuery = `
      SELECT id FROM users
      WHERE email = $1 AND tenant_id = $2
      LIMIT 1;
    `;
    const existingUser = await db.query(existingUserQuery, [normalizedEmail, tenantId]);

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Já existe um usuário cadastrado com este e-mail nesta empresa.' });
    }

    // 4. Criptografia segura da senha (Fator de custo 12)
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // 5. Inserção no banco de dados vinculando obrigatoriamente o tenant_id
    const insertUserQuery = `
      INSERT INTO users (tenant_id, name, email, password_hash, created_at, updated_at)
      VALUES ($1, $2, $3, $4, NOW(), NOW())
      RETURNING id, tenant_id, name, email, created_at;
    `;

    const { rows } = await db.query(insertUserQuery, [
      tenantId,
      name.trim(),
      normalizedEmail,
      passwordHash
    ]);

    const createdUser = rows[0];

    // 6. Retorno dos dados do usuário criado (nunca expor o hash da senha)
    return res.status(201).json({
      message: 'Usuário cadastrado com sucesso.',
      user: {
        id: createdUser.id,
        tenantId: createdUser.tenant_id,
        name: createdUser.name,
        email: createdUser.email,
        createdAt: createdUser.created_at
      }
    });

  } catch (error) {
    console.error('[CreateUserError]:', error);
    return res.status(500).json({ error: 'Erro interno ao realizar o cadastro do usuário.' });
  }
});

module.exports = router;