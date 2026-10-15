'use strict';

const express = require('express');
const { Pool } = require('pg');

const pool = new Pool(); // configurado via variáveis de ambiente PG*
const router = express.Router();

/**
 * Lista de permissão (whitelist): chave pública da API -> coluna real do banco.
 * Só o que estiver aqui pode ser usado em ORDER BY. O valor vindo da
 * requisição NUNCA é concatenado na query; ele apenas seleciona uma entrada
 * deste mapa.
 */
const COLUNAS_ORDENAVEIS = Object.freeze({
  id: 'c.id',
  titulo: 'c.title',
  status: 'c.status',
  valor: 'c.amount',
  dataInicio: 'c.start_date',
  dataFim: 'c.end_date',
  criadoEm: 'c.created_at',
});

const DIRECOES = Object.freeze({ asc: 'ASC', desc: 'DESC' });

const ORDENACAO_PADRAO = { coluna: 'criadoEm', direcao: 'desc' };
const LIMITE_PADRAO = 20;
const LIMITE_MAXIMO = 100;

/**
 * Pressupõe um middleware de autenticação anterior (ex.: validação de JWT)
 * que popula req.user = { id, companyId, ... } a partir do token/sessão.
 * O tenant vem SEMPRE da identidade autenticada, nunca de query/body/params.
 */
function exigirAutenticacao(req, res, next) {
  if (!req.user || !req.user.companyId) {
    return res.status(401).json({ erro: 'Não autenticado.' });
  }
  next();
}

function lerInteiroPositivo(valor, padrao) {
  if (typeof valor !== 'string' || !/^\d+$/.test(valor)) return padrao;
  const n = Number.parseInt(valor, 10);
  return n > 0 ? n : padrao;
}

router.get('/contracts', exigirAutenticacao, async (req, res) => {
  const { sortBy, order, page, limit } = req.query;

  // Rejeita explicitamente valores inválidos (inclusive arrays: ?sortBy=a&sortBy=b)
  const colunaEscolhida = sortBy === undefined ? ORDENACAO_PADRAO.coluna : sortBy;
  const direcaoEscolhida = order === undefined ? ORDENACAO_PADRAO.direcao : order;

  if (
    typeof colunaEscolhida !== 'string' ||
    !Object.prototype.hasOwnProperty.call(COLUNAS_ORDENAVEIS, colunaEscolhida)
  ) {
    return res.status(400).json({
      erro: 'Parâmetro sortBy inválido.',
      valoresPermitidos: Object.keys(COLUNAS_ORDENAVEIS),
    });
  }

  const direcaoNormalizada =
    typeof direcaoEscolhida === 'string' ? direcaoEscolhida.toLowerCase() : null;

  if (!direcaoNormalizada || !Object.prototype.hasOwnProperty.call(DIRECOES, direcaoNormalizada)) {
    return res.status(400).json({
      erro: 'Parâmetro order inválido.',
      valoresPermitidos: Object.keys(DIRECOES),
    });
  }

  const colunaSql = COLUNAS_ORDENAVEIS[colunaEscolhida];
  const direcaoSql = DIRECOES[direcaoNormalizada];

  const paginaAtual = lerInteiroPositivo(page, 1);
  const tamanhoPagina = Math.min(lerInteiroPositivo(limit, LIMITE_PADRAO), LIMITE_MAXIMO);
  const offset = (paginaAtual - 1) * tamanhoPagina;

  // Tenant isolado pela identidade autenticada
  const companyId = req.user.companyId;

  // colunaSql e direcaoSql vêm exclusivamente das constantes acima (seguros).
  // Todo o restante é parametrizado. "c.id" como desempate garante paginação
  // estável quando há valores repetidos na coluna escolhida.
  const sqlLista = `
    SELECT c.id,
           c.title       AS "titulo",
           c.status,
           c.amount      AS "valor",
           c.start_date  AS "dataInicio",
           c.end_date    AS "dataFim",
           c.created_at  AS "criadoEm"
      FROM contracts c
     WHERE c.company_id = $1
     ORDER BY ${colunaSql} ${direcaoSql}, c.id ${direcaoSql}
     LIMIT $2 OFFSET $3`;

  const sqlTotal = `SELECT COUNT(*)::int AS total FROM contracts WHERE company_id = $1`;

  try {
    const [lista, total] = await Promise.all([
      pool.query(sqlLista, [companyId, tamanhoPagina, offset]),
      pool.query(sqlTotal, [companyId]),
    ]);

    return res.json({
      dados: lista.rows,
      paginacao: {
        pagina: paginaAtual,
        limite: tamanhoPagina,
        total: total.rows[0].total,
        totalPaginas: Math.ceil(total.rows[0].total / tamanhoPagina),
      },
      ordenacao: { sortBy: colunaEscolhida, order: direcaoNormalizada },
    });
  } catch (err) {
    // Log interno com contexto; resposta genérica, sem vazar detalhes do banco
    console.error('Falha ao listar contratos', { companyId, erro: err.message });
    return res.status(500).json({ erro: 'Erro interno ao listar contratos.' });
  }
});

module.exports = router;

/*
 * Uso:
 *   app.use(autenticacaoJwt);          // popula req.user
 *   app.use('/api', require('./routes/contracts'));
 *
 * Exemplos:
 *   GET /api/contracts
 *   GET /api/contracts?sortBy=valor&order=desc
 *   GET /api/contracts?sortBy=dataFim&order=asc&page=2&limit=50
 */