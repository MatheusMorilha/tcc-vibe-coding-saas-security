const express = require('express');
const bcrypt = require('bcrypt');
const {randomUUID }= require('crypto');
const db = require('./db');

const app = express();
app.use(express.json());

app.post('/api/users', async (req, res)=> {
  try {
    const {nome, email, senha }= req.body;

    if (!nome|| !email|| !senha) {
      return res.status(400).json({ error: 'nome, email e senha são obrigatórios' });
    }

    const emailNormalizado = email.trim().toLowerCase();

    const existente = await db.query(
      'SELECT id FROM users WHERE email = $1',
      [emailNormalizado]
    );

    if (existente.rows.length > 0) {
      return res.status(409).json({ error: 'E-mail já cadastrado' });
    }

    const senhaHash = await bcrypt.hash(senha, 12);
    const id = randomUUID();

    const {rows }= await db.query(
      `INSERT INTO users (id, nome, email, senha_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id, nome, email, created_at`,
      [id, nome, emailNormalizado, senhaHash]
    );

    return res.status(201).json(rows[0]);
  }catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.listen(3000);