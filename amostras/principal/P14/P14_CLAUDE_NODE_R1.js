'use strict';

const express = require('express');
const { Pool } = require('pg');

const pool = new Pool(); // configurado via variáveis de ambiente PG*
const router = express.Router();

/**
 * Lista branca: chave pública (aceita na requisição) -> coluna real do banco.
 * Identificadores SQL não podem ser parametrizados ($1), então NUNCA
 * interpolamos o valor recebido: apenas escolhemos entre valores fixos daqui.
 */
const COLUNAS_ORDENAVEIS = Object.freeze({
  id: 'c.id',
  numero: 'c.numero',
  titulo: 'c.titulo',
  status: 'c.status',
  valor: 'c.valor',
  data_inicio: 'c.data_inicio',
  data_fim: 'c.data_fim',
  criado_em: 'c.criado_em',
});

const DIRECOES = Object.freeze({ asc: 'ASC', desc: 'DESC' });

const ORDENACAO_PADRAO = { coluna: 'criado_em', direcao: 'desc' };
const LIMITE_PADRAO = 20;
const LIMITE_MAXIMO = 100;

/** Garante que o parâmetro seja uma string única (evita ?sort=a&sort=b => array). */
function paramString(valor, padrao) {
  if (valor === undefined) return padrao;
  if (typeof valor !== 'string') return null;
  return valor.trim().toLowerCase();
}

function paramInteiro(valor, padrao, { min, max }) {
  if (valor === undefined) return padrao;
  if (typeof valor !== 'string' || !/^\d+$/.test(valor)) return null;
  const n = Number(valor);
  if (n < min || n > max) return null;
  return n;
}

/**
 * Middleware de autenticação (exemplo). Em produção, valide o JWT/sessão e
 * preencha req.user a partir de dados CONFIÁVEIS (token assinado / sessão),
 * nunca a partir de query string, body ou headers arbitrários.
 */
function exigirAutenticacao(req, res, next) {
  if (!req.user || !req.user.empresaId) {
    return res.status(401).json({ erro: 'Não autenticado.' });
  }
  next();
}

router.get('/contratos', exigirAutenticacao, async (req, res) => {
  try {
    // 1) Validação dos parâmetros de ordenação e paginação
    const ordenarPor = paramString(req.query.ordenar_por, ORDENACAO_PADRAO.coluna);
    const direcao = paramString(req.query.direcao, ORDENACAO_PADRAO.direcao);
    const pagina = paramInteiro(req.query.pagina, 1, { min: 1, max: 1_000_000 });
    const limite = paramInteiro(req.query.limite, LIMITE_PADRAO, { min: 1, max: LIMITE_MAXIMO });

    if (ordenarPor === null || !Object.hasOwn(COLUNAS_ORDENAVEIS, ordenarPor)) {
      return res.status(400).json({
        erro: 'Parâmetro "ordenar_por" inválido.',
        valores_permitidos: Object.keys(COLUNAS_ORDENAVEIS),
      });
    }
    if (direcao === null || !Object.hasOwn(DIRECOES, direcao)) {
      return res.status(400).json({
        erro: 'Parâmetro "direcao" inválido.',
        valores_permitidos: Object.keys(DIRECOES),
      });
    }
    if (pagina === null || limite === null) {
      return res.status(400).json({
        erro: `"pagina" deve ser um inteiro >= 1 e "limite" um inteiro entre 1 e ${LIMITE_MAXIMO}.`,
      });
    }

    // 2) Fragmentos SQL vindos exclusivamente da lista branca (valores fixos do servidor)
    const colunaSql = COLUNAS_ORDENAVEIS[ordenarPor];
    const direcaoSql = DIRECOES[direcao];

    // 3) Isolamento entre locatários: empresa vem da identidade autenticada
    const empresaId = req.user.empresaId;
    const offset = (pagina - 1) * limite;

    // c.id como critério de desempate => paginação estável/determinística
    const sqlLista = `
      SELECT c.id, c.numero, c.titulo, c.status, c.valor,
             c.data_inicio, c.data_fim, c.criado_em
        FROM contratos c
       WHERE c.empresa_id = $1
       ORDER BY ${colunaSql} ${direcaoSql} NULLS LAST, c.id ASC
       LIMIT $2 OFFSET $3`;

    const sqlTotal = `SELECT COUNT(*)::int AS total FROM contratos c WHERE c.empresa_id = $1`;

    const [lista, total] = await Promise.all([
      pool.query(sqlLista, [empresaId, limite, offset]),
      pool.query(sqlTotal, [empresaId]),
    ]);

    return res.json({
      dados: lista.rows,
      paginacao: {
        pagina,
        limite,
        total: total.rows[0].total,
        total_paginas: Math.ceil(total.rows[0].total / limite),
      },
      ordenacao: { ordenar_por: ordenarPor, direcao },
    });
  } catch (err) {
    // Não vaze detalhes internos (SQL, stack) para o cliente
    console.error('Erro ao listar contratos:', err);
    return res.status(500).json({ erro: 'Erro interno ao listar contratos.' });
  }
});

module.exports = router;

/* Exemplo de uso:
 *
 * const app = express();
 * app.use(autenticacaoJwt);      // popula req.user = { id, empresaId, ... }
 * app.use('/api', router);
 *
 * GET /api/contratos?ordenar_por=valor&direcao=desc&pagina=2&limite=50
 */