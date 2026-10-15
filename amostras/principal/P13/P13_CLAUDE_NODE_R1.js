'use strict';

const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

/* ------------------------------------------------------------------ */
/* Autenticação: o tenant é extraído do token verificado no servidor.  */
/* ------------------------------------------------------------------ */
function autenticar(req, res, next) {
  const header = req.headers.authorization || '';
  const [tipo, token] = header.split(' ');

  if (tipo !== 'Bearer' || !token) {
    return res.status(401).json({ erro: 'Não autenticado.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
    });

    if (!payload.empresaId) {
      return res.status(403).json({ erro: 'Token sem empresa associada.' });
    }

    req.usuario = { id: payload.sub, empresaId: payload.empresaId };
    return next();
  } catch (err) {
    return res.status(401).json({ erro: 'Token inválido ou expirado.' });
  }
}

/* Escapa curingas do LIKE para que o filtro seja tratado como texto literal */
function escaparLike(texto) {
  return texto.replace(/[\\%_]/g, (c) => '\\' + c);
}

/* ------------------------------------------------------------------ */
/* GET /api/clientes?nome=maria&pagina=1&limite=20                     */
/* ------------------------------------------------------------------ */
router.get('/api/clientes', autenticar, async (req, res) => {
  try {
    // ---- Validação dos parâmetros ----
    const { nome } = req.query;

    if (nome !== undefined && (typeof nome !== 'string' || nome.length > 100)) {
      return res.status(400).json({ erro: 'Parâmetro "nome" inválido.' });
    }

    const pagina = Math.max(parseInt(req.query.pagina, 10) || 1, 1);
    const limite = Math.min(Math.max(parseInt(req.query.limite, 10) || 20, 1), 100);
    const offset = (pagina - 1) * limite;

    // ---- Consulta parametrizada, SEMPRE restrita ao tenant do token ----
    const params = [req.usuario.empresaId];
    let where = 'WHERE empresa_id = $1';

    const termo = (nome || '').trim();
    if (termo) {
      params.push(`%${escaparLike(termo)}%`);
      where += ` AND nome ILIKE $${params.length} ESCAPE '\\'`;
    }

    params.push(limite, offset);
    const sql = `
      SELECT id, nome, email, telefone, criado_em,
             COUNT(*) OVER() AS total
        FROM clientes
        ${where}
       ORDER BY nome ASC, id ASC
       LIMIT $${params.length - 1} OFFSET $${params.length}
    `;

    const { rows } = await pool.query(sql, params);
    const total = rows.length ? Number(rows[0].total) : 0;

    return res.json({
      dados: rows.map(({ total: _t, ...cliente }) => cliente),
      paginacao: {
        pagina,
        limite,
        total,
        totalPaginas: Math.ceil(total / limite),
      },
    });
  } catch (err) {
    console.error('Erro ao listar clientes:', err);
    return res.status(500).json({ erro: 'Erro interno do servidor.' });
  }
});

module.exports = router;

/* ------------------------------------------------------------------ */
/* Uso no app principal:                                               */
/*   const app = express();                                            */
/*   app.use(require('./rotas/clientes'));                             */
/*   app.listen(3000);                                                 */
/* ------------------------------------------------------------------ */