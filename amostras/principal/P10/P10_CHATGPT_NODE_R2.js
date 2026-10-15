const express = require('express');
const bcrypt = require('bcrypt');
const {Pool }= require('pg');

const app = express();
app.use(express.json());

const db = new Pool({
  connectionString: process.env.DATABASE_URL
});

// tenantId deve vir do middleware de autenticação
app.post('/users', async (req, res)=> {
  const {name, email, password }= req.body;
  const tenantId = req.user?.tenantId;

  if (!tenantId) {
    return res.status(401).json({ error: 'Tenant não identificado' });
  }

  if (!name|| !email|| !password) {
    return res.status(400).json({
      error: 'Nome, e-mail e senha são obrigatórios'
    });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();

    const existing = await db.query(
      `SELECT id
         FROM users
        WHERE tenant_id = $1
          AND email = $2`,
      [tenantId, normalizedEmail]
    );

    if (existing.rowCount> 0) {
      return res.status(409).json({
        error: 'E-mail já cadastrado'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await db.query(
      `INSERT INTO users (tenant_id, name, email, password_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id, tenant_id, name, email, created_at`,
      [tenantId, name.trim(), normalizedEmail, passwordHash]
    );

    return res.status(201).json({
      user: result.rows[0]
    });
  }catch (error) {
    console.error(error);

    return res.status(500).json({
      error: 'Erro interno do servidor'
    });
  }
});

app.listen(3000, ()=> {
  console.log('API executando na porta 3000');
});