'use strict';

const express = require('express');
const { Pool } = require('pg');

const router = express.Router();
const pool = new Pool(); // usa as variáveis PG* do ambiente

// ---------------------------------------------------------------------------
// Whitelist: o que o cliente envia é apenas uma CHAVE de lookup.
// O identificador SQL real vem sempre daqui, nunca da requisição.
// ---------------------------------------------------------------------------
const COLUNAS_ORDENAVEIS = Object.freeze({
  numero: 'c.numero',
  titulo: 'c.titulo',
  status: 'c.status',
  valor: 'c.valor',
  data_inicio: 'c.data_inicio',
  data_fim: 'c.data_fim',
  criado_em: 'c.criado_em',
});

const DIRECOES = Object.freeze({ asc: 'ASC', desc: 'DESC' });

const ORDENACAO_PADRAO = 'criado_em';
const DIRECAO_PADRAO = 'desc';
const LIMITE_PADRAO = 20;
const LIMITE_MAXIMO = 100;

// Lê um parâmetro de query garantindo que seja string simples
// (evita ?ordenarPor[]=x ou ?ordenarPor=a&ordenarPor=b virarem array/objeto).
function lerString(valor) {
  return typeof valor === 'string' ? valor.trim().toLowerCase() : undefined;
}

function lerInteiroPositivo(valor, padrao) {
  if (valor === undefined) return padrao;
  if (typeof valor !== 'string' || !/^\d+$/.test(valor)) return null;
  const n = Number(valor);
  return n > 0 ? n : null;
}

// ---------------------------------------------------------------------------
// GET /contratos?ordenarPor=valor&direcao=desc&pagina=1&limite=20
//
// Pressupõe um middleware de autenticação anterior que valida o token e
// preenche req.usuario = { id, empresaId, permissoes: [...] }.
// O tenant vem EXCLUSIVAMENTE da sessão autenticada.
// ---------------------------------------------------------------------------
router.get('/contratos', async (req, res) => {
  try {
    const { usuario } = req;

    if (!usuario || !usuario.empresaId) {
      return res.status(401).json({ erro: 'Não autenticado.' });
    }

    // (opcional) autorização por permissão
    if (!usuario.permissoes?.includes('contratos:ler')) {
      return res.status(403).json({ erro: 'Sem permissão para listar contratos.' });
    }

    // --- validação da ordenação ------------------------------------------
    const ordenarPor = lerString(req.query.ordenarPor) ?? ORDENACAO_PADRAO;
    const direcao = lerString(req.query.direcao) ?? DIRECAO_PADRAO;

    if (!Object.hasOwn(COLUNAS_ORDENAVEIS, ordenarPor)) {
      return res.status(400).json({
        erro: 'Parâmetro "ordenarPor" inválido.',
        valoresAceitos: Object.keys(COLUNAS_ORDENAVEIS),
      });
    }
    if (!Object.hasOwn(DIRECOES, direcao)) {
      return res.status(400).json({
        erro: 'Parâmetro "direcao" inválido.',
        valoresAceitos: Object.keys(DIRECOES),
      });
    }

    // --- validação da paginação ------------------------------------------
    const pagina = lerInteiroPositivo(req.query.pagina, 1);
    const limiteSolicitado = lerInteiroPositivo(req.query.limite, LIMITE_PADRAO);

    if (pagina === null || limiteSolicitado === null) {
      return res.status(400).json({ erro: '"pagina" e "limite" devem ser inteiros positivos.' });
    }

    const limite = Math.min(limiteSolicitado, LIMITE_MAXIMO);
    const offset = (pagina - 1) * limite;

    // --- montagem da query -----------------------------------------------
    // Colunas e direção vêm das whitelists; valores vão como parâmetros ($n).
    // "c.id" como desempate garante paginação estável entre páginas.
    const colunaSql = COLUNAS_ORDENAVEIS[ordenarPor];
    const direcaoSql = DIRECOES[direcao];

    const sqlListagem = `
      SELECT c.id, c.numero, c.titulo, c.status, c.valor,
             c.data_inicio, c.data_fim, c.criado_em
        FROM contratos c
       WHERE c.empresa_id = $1
       ORDER BY ${colunaSql} ${direcaoSql} NULLS LAST, c.id ASC
       LIMIT $2 OFFSET $3`;

    const sqlTotal = `SELECT COUNT(*)::int AS total FROM contratos WHERE empresa_id = $1`;

    const [listagem, total] = await Promise.all([
      pool.query(sqlListagem, [usuario.empresaId, limite, offset]),
      pool.query(sqlTotal, [usuario.empresaId]),
    ]);

    return res.json({
      dados: listagem.rows,
      paginacao: {
        pagina,
        limite,
        total: total.rows[0].total,
        totalPaginas: Math.ceil(total.rows[0].total / limite),
      },
      ordenacao: { ordenarPor, direcao },
    });
  } catch (err) {
    // Não vaza detalhes internos ao cliente
    console.error('Erro ao listar contratos:', err);
    return res.status(500).json({ erro: 'Erro interno ao listar contratos.' });
  }
});

module.exports = router;