const http = require('http');
const {Pool }= require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

function parseDate(value, fieldName) {
  if (!value|| !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new Error(`${fieldName} deve estar no formato YYYY-MM-DD`);
  }

  const date = new Date(`${value}T00:00:00.000Z`);

  if (Number.isNaN(date.getTime())) {
    throw new Error(`${fieldName} inválida`);
  }

  return date;
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8'
  });

  res.end(JSON.stringify(data));
}

async function gerarRelatorioFinanceiro(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);

    const empresaId = url.searchParams.get('empresaId');
    const inicio = url.searchParams.get('inicio');
    const fim = url.searchParams.get('fim');

    if (!empresaId|| !inicio|| !fim) {
      return sendJson(res, 400, {
        erro: 'Os parâmetros empresaId, inicio e fim são obrigatórios.'
      });
    }

    const dataInicio = parseDate(inicio, 'inicio');
    const dataFim = parseDate(fim, 'fim');

    if (dataInicio> dataFim) {
      return sendJson(res, 400, {
        erro: 'A data inicial não pode ser posterior à data final.'
      });
    }

    /*
     * Validação simples do identificador.
     * Caso seja UUID, pode-se substituir por uma validação de UUID.
     */
    if (!/^[a-zA-Z0-9_-]+$/.test(empresaId)) {
      return sendJson(res, 400, {
        erro: 'empresaId inválido.'
      });
    }

    const client = await pool.connect();

    try {
      /*
       * Verifica se a empresa existe.
       */
      const empresaResult = await client.query(
        `
        SELECT
          id,
          nome
        FROM empresas
        WHERE id = $1
        `,
        [empresaId]
      );

      if (empresaResult.rowCount=== 0) {
        return sendJson(res, 404, {
          erro: 'Empresa não encontrada.'
        });
      }

      /*
       * Consolidamos receitas e despesas separadamente.
       *
       * IMPORTANTE:
       * Todas as consultas possuem empresa_id = $1.
       * Isso impede que registros financeiros de outros
       * tenants sejam incluídos no relatório.
       *
       * O limite superior é exclusivo:
       *
       *   data >= inicio
       *   data < fim + 1 dia
       *
       * Dessa forma, todo o último dia é incluído,
       * independentemente do horário registrado.
       */
      const resultado = await client.query(
        `
        SELECT
          COALESCE(
            SUM(
              CASE
                WHEN tipo = 'RECEITA' THEN valor
                ELSE 0
              END
            ),
            0
          ) AS receitas,

          COALESCE(
            SUM(
              CASE
                WHEN tipo = 'DESPESA' THEN valor
                ELSE 0
              END
            ),
            0
          ) AS despesas,

          COUNT(*) AS quantidade_lancamentos

        FROM lancamentos_financeiros

        WHERE empresa_id = $1
          AND data_lancamento >= $2
          AND data_lancamento < ($3::date + INTERVAL '1 day')
        `,
        [empresaId, inicio, fim]
      );

      const dados = resultado.rows[0];

      const receitas = Number(dados.receitas);
      const despesas = Number(dados.despesas);
      const saldo = receitas- despesas;

      const relatorio = {
        empresa: {
          id: empresaResult.rows[0].id,
          nome: empresaResult.rows[0].nome
        },

        periodo: {
          inicio,
          fim
        },

        financeiro: {
          receitas,
          despesas,
          saldo
        },

        quantidadeLancamentos: Number(
          dados.quantidade_lancamentos
        )
      };

      return sendJson(res, 200, relatorio);

    }finally {
      client.release();
    }

  }catch (error) {
    console.error('Erro ao gerar relatório financeiro:', error);

    return sendJson(res, 500, {
      erro: 'Não foi possível gerar o relatório financeiro.'
    });
  }
}

const server = http.createServer(async (req, res)=> {
  if (
    req.method=== 'GET' &&
    req.url.startsWith('/api/relatorios/financeiro')
  ) {
    return gerarRelatorioFinanceiro(req, res);
  }

  sendJson(res, 404, {
    erro: 'Rota não encontrada.'
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, ()=> {
  console.log(`API executando na porta${PORT}`);
});