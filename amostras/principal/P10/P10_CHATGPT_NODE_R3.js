const express = require('express');
const bcrypt = require('bcrypt');
const {Pool }= require('pg');

const app = express();
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.post('/users', async (req, res)=> {
  const {name, email, password }= req.body;

  if (!name|| !email|| !password) {
    return res.status(400).json({ error: 'name, email e password são obrigatórios' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    const {rows }= await pool.query(
      `INSERT INTO users (name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, name, email, created_at`,
      [name, email, passwordHash]
    );

    return res.status(201).json(rows[0]);
  }catch (err) {
    if (err.code=== '23505') {
      return res.status(409).json({ error: 'E-mail já cadastrado' });
    }

    return res.status(500).json({ error: 'Erro interno' });
  }
});

app.listen(3000);