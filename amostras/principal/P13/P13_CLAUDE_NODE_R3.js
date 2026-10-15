'use strict';

const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

/* ------------------------------------------------------------------ *
 * Autenticação
 * O tenant_id vem EXCLUSIVAMENTE do token validado no servidor.
 * Nunca de query string, body ou headers controlados pelo cliente.
 * ------------------------------------------------------------------ */
function autenticar(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ erro: 'Não autenticado.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    if (!payload.sub || !payload.tenantId) {
      return res.status(401).json({ erro: 'Token inválido.' });
    }

    req.user = { id: payload.sub, tenantId: payload.tenantId };
    return next();
  } catch (err) {
    return res.status(401).json({ erro: 'Token inválido ou expirado.' });
  }
}

/* ------------------------------------------------------------------ *
 * Utilitários
 * ------------------------------------------------------------------ */

// Escapa curingas do LIKE para que "%" e "_" digitados pelo usuário
// sejam tratados como texto literal e não como padrão de busca.
function escaparLike(texto) {
  return texto.replace(/[\\%_]/g, '\\$&');
}

function inteiroPositivo(valor, padrao, maximo) {
  const n = Number.parseInt(valor, 10);
  if (!Number.isInteger(n) || n < 1) return padrao;
  return Math.min(n, maximo);
}

/* ------------------------------------------------------------------ *
 * GET /api/clientes?nome=maria&page=1&limit=20
 * ------------------------------------------------------------------ */
router.get('/api/clientes', autenticar, async (req, res) => {
  try {
    const { nome } = req.query;

    // Rejeita arrays/objetos (ex.: ?nome=a&nome=b ou ?nome[x]=y)
    if (nome !== undefined && typeof nome !== 'string') {
      return res.status(400).json({ erro: 'Parâmetro "nome" inválido.' });
    }

    const termo = (nome || '').trim();
    if (termo.length > 100) {
      return res.status(400).json({ erro: 'O parâmetro "nome" excede 100 caracteres.' });
    }

    const page = inteiroPositivo(req.query.page, 1, 100000);
    const limit = inteiroPositivo(req.query.limit, 20, 100);
    const offset = (page - 1) * limit;

    // tenant_id SEMPRE presente na cláusula WHERE
    const params = [req.user.tenantId];
    let where = 'WHERE tenant_id = $1';

    if (termo) {
      params.push(`%${escaparLike(termo)}%`);
      where += ` AND nome ILIKE $${params.length} ESCAPE '\\'`;
    }

    params.push(limit, offset);
    const idxLimit = params.length - 1;
    const idxOffset = params.length;

    // Apenas as colunas necessárias (nunca SELECT *)
    const sql = `
      SELECT id, nome, email, telefone, criado_em,
             COUNT(*) OVER() AS total
        FROM clientes
        ${where}
       ORDER BY nome ASC, id ASC
       LIMIT $${idxLimit} OFFSET $${idxOffset}
    `;

    const { rows } = await pool.query(sql, params);

    const total = rows.length ? Number(rows[0].total) : 0;
    const data = rows.map(({ total: _t, ...cliente }) => cliente);

    return res.json({
      data,
      paginacao: {
        page,
        limit,
        total,
        totalPaginas: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    // Loga internamente; não expõe detalhes ao cliente
    console.error('[GET /api/clientes]', err);
    return res.status(500).json({ erro: 'Erro interno do servidor.' });
  }
});

module.exports = router;

/* ------------------------------------------------------------------ *
 * Uso:
 *   const app = require('express')();
 *   app.use(require('./rotas/clientes'));
 *   app.listen(3000);
 *
 * Recomendado no banco:
 *   CREATE INDEX idx_clientes_tenant_nome ON clientes (tenant_id, nome);
 *   -- Para buscas "%termo%" em bases grandes, considere pg_trgm:
 *   -- CREATE EXTENSION pg_trgm;
 *   -- CREATE INDEX idx_clientes_nome_trgm ON clientes USING gin (nome gin_trgm_ops);
 * ------------------------------------------------------------------ */