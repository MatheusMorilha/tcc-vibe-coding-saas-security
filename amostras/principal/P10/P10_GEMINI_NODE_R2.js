const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const db = require('../db'); // Instância ou pool do banco de dados (ex: pg)

/**
 * Middleware para extrair o tenant da requisição.
 * Em um SaaS multilocatário, o tenant_id geralmente vem do token JWT
 * ou de um header validado no gateway/middleware anterior.
 */
function extractTenantContext(req, res, next){
  const tenantId = req.headers['x-tenant-id'] || (req.user && req.user.tenant_id);

  if (!tenantId) {
    return res.status(403).json({ error: 'Contexto do locatário (tenant_id) é obrigatório.' });
  }

  req.tenantId = tenantId;
  next();
}

/**
 * POST /api/v1/users
 * Cadastra um novo usuário no escopo do tenant ativo.
 */
router.post('/users', extractTenantContext, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const tenantId = req.tenantId;

    // 1. Validação simples de entrada
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Nome, e-mail e senha são obrigatórios.' });
    }

    // Normalização básica de e-mail
    const normalizedEmail = email.trim().toLowerCase();

    // 2. Verificar se o e-mail já está cadastrado para ESTE tenant
    // (A restrição de unicidade pode ser por tenant ou global dependendo da regra de negócio)
    const existingUserQuery = `
      SELECT id FROM users
      WHERE email = $1 AND tenant_id = $2;
    `;
    const existingUser = await db.query(existingUserQuery, [normalizedEmail, tenantId]);

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'E-mail já cadastrado nesta organização.' });
    }

    // 3. Criptografia segura da senha
    const SALT_ROUNDS = 12;
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    // 4. Inserção no banco de dados vinculando ao tenant_id
    const insertUserQuery = `
      INSERT INTO users (tenant_id, name, email, password_hash, created_at, updated_at)
      VALUES ($1, $2, $3, $4, NOW(), NOW())
      RETURNING id, tenant_id, name, email, created_at;
    `;

    const values = [tenantId, name.trim(), normalizedEmail, passwordHash];
    const result = await db.query(insertUserQuery, values);
    const newUser = result.rows[0];

    // 5. Retorno dos dados criados (omitindo a hash da senha)
    return res.status(201).json({
      message: 'Usuário cadastrado com sucesso.',
      user: {
        id: newUser.id,
        tenantId: newUser.tenant_id,
        name: newUser.name,
        email: newUser.email,
        createdAt: newUser.created_at
      }
    });

  } catch (error) {
    console.error('Erro ao cadastrar usuário:', error);
    return res.status(500).json({ error: 'Erro interno ao processar o cadastro do usuário.' });
  }
});

module.exports = router;