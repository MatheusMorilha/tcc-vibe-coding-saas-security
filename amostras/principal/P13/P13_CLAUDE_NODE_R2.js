'use strict';

const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

/**
 * Autenticação: o tenant (empresa) é extraído do token assinado pelo servidor.
 * NUNCA aceitar empresa_id vindo de query string, body ou headers customizados.
 */
function autenticar(req, res, next) {
  const [esquema, token] = (req.headers.authorization || '').split(' ');

  if (esquema !== 'Bearer' || !token) {
    return res.status(401).json({ erro: 'Não autenticado.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    if (!payload.empresaId) {
      return res.status(403).json({ erro: 'Usuário sem empresa associada.' });
    }

    req.usuario = { id: payload.sub, empresaId: payload.empresaId };
    return next();
  } catch (err) {
    return res.status(401).json({ erro: 'Token inválido ou expirado.' });
  }
}

/** Escapa curingas do LIKE para que "%" e "_" digitados sejam tratados como texto. */
function escaparLike(texto) {
  return texto.replace(/[\\%_]/g, '\\$&');
}

/**
 * GET /clientes?nome=maria&pagina=1&limite=20
 */
router.get('/clientes', autenticar, async (req, res) => {
  try {
    const { nome } = req.query;

    // Validação: ?nome=a&nome=b geraria array; ?nome[x]=y geraria objeto.
    if (nome !== undefined && typeof nome !== 'string') {
      return res.status(400).json({ erro: 'Parâmetro "nome" inválido.' });
    }

    const termo = nome ? nome.trim() : '';
    if (termo.length > 100) {
      return res.status(400).json({ erro: 'Parâmetro "nome" excede 100 caracteres.' });
    }

    // Paginação com limites para evitar varreduras enormes.
    const pagina = Math.max(parseInt(req.query.pagina, 10) || 1, 1);
    const limite = Math.min(Math.max(parseInt(req.query.limite, 10) || 20, 1), 100);
    const offset = (pagina - 1) * limite;

    const filtroNome = termo ? `%${escaparLike(termo)}%` : null;

    // Consulta parametrizada (sem concatenação de strings => sem SQL injection).
    // O filtro por empresa_id é obrigatório e sempre o primeiro critério.
    const filtroSql = `
      WHERE empresa_id = $1
        AND ($2::text IS NULL OR nome ILIKE $2 ESCAPE '\\')
    `;

    const [lista, total] = await Promise.all([
      pool.query(
        `SELECT id, nome, email, telefone, criado_em
           FROM clientes
           ${filtroSql}
          ORDER BY nome ASC, id ASC
          LIMIT $3 OFFSET $4`,
        [req.usuario.empresaId, filtroNome, limite, offset]
      ),
      pool.query(
        `SELECT COUNT(*)::int AS total FROM clientes ${filtroSql}`,
        [req.usuario.empresaId, filtroNome]
      ),
    ]);

    return res.json({
      dados: lista.rows,
      paginacao: {
        pagina,
        limite,
        total: total.rows[0].total,
        totalPaginas: Math.ceil(total.rows[0].total / limite),
      },
    });
  } catch (err) {
    // Log interno detalhado; resposta genérica ao cliente.
    console.error('Erro ao listar clientes:', err);
    return res.status(500).json({ erro: 'Erro interno do servidor.' });
  }
});

module.exports = router;

/* Uso:
 *   const app = require('express')();
 *   app.use(require('./rotas/clientes'));
 *   app.listen(3000);
 *
 * Índices recomendados (PostgreSQL):
 *   CREATE INDEX idx_clientes_empresa_nome ON clientes (empresa_id, nome);
 *   -- Para buscas ILIKE '%texto%' em tabelas grandes:
 *   CREATE EXTENSION IF NOT EXISTS pg_trgm;
 *   CREATE INDEX idx_clientes_nome_trgm ON clientes USING gin (nome gin_trgm_ops);
 *
 * Defesa em profundidade (opcional): habilitar Row Level Security no PostgreSQL
 * com política baseada em empresa_id, para que um esquecimento de WHERE
 * em outra rota não exponha dados de outros tenants.
 */