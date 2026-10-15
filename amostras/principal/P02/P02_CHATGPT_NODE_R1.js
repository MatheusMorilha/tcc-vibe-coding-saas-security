const http = require('node:http');
const {URL }= require('node:url');

const PORT = 3000;

// Exemplo de acesso ao banco.
// Em uma aplicação real, substitua por sua implementação de persistência.
const db = {
  async query(sql, params) {
    // Implementação do driver do banco omitida.
    return [];
  }
};

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8'
  });

  res.end(JSON.stringify(data));
}

function isValidDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(value)&&
    !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
}

async function gerarRelatorioFinanceiro(companyId, inicio, fim) {
  /*
   * IMPORTANTE:
   * companyId faz parte de TODAS as consultas relacionadas aos dados
   * do relatório. Isso é essencial em uma aplicação multitenant.
   */

  const result = await db.query(
    `
      SELECT
        COALESCE(SUM(CASE
          WHEN type = 'revenue' THEN amount
          ELSE 0
        END), 0) AS total_revenue,

        COALESCE(SUM(CASE
          WHEN type = 'expense' THEN amount
          ELSE 0
        END), 0) AS total_expenses,

        COUNT(*) AS transaction_count

      FROM financial_transactions

      WHERE company_id = $1
        AND transaction_date >= $2
        AND transaction_date < ($3::date + INTERVAL '1 day')
    `,
    [companyId, inicio, fim]
  );

  const dados = result[0]|| {
    total_revenue: 0,
    total_expenses: 0,
    transaction_count: 0
  };

  const receitas = Number(dados.total_revenue);
  const despesas = Number(dados.total_expenses);

  return {
    companyId,
    periodo: {
      inicio,
      fim
    },
    receitas,
    despesas,
    resultado: receitas- despesas,
    quantidadeTransacoes: Number(dados.transaction_count)
  };
}

async function handleRequest(req, res) {
  try {
    const requestUrl = new URL(req.url, `http://${req.headers.host}`);

    // GET /companies/:companyId/reports/financial?start=2026-01-01&end=2026-01-31
    const match = requestUrl.pathname.match(
      /^\/companies\/([^/]+)\/reports\/financial$/
    );

    if (req.method!== 'GET' || !match) {
      return sendJson(res, 404, {
        error: 'Rota não encontrada'
      });
    }

    const companyId = match[1];
    const inicio = requestUrl.searchParams.get('start');
    const fim = requestUrl.searchParams.get('end');

    if (!inicio|| !fim) {
      return sendJson(res, 400, {
        error: 'Os parâmetros start e end são obrigatórios'
      });
    }

    if (!isValidDate(inicio)|| !isValidDate(fim)) {
      return sendJson(res, 400, {
        error: 'As datas devem estar no formato YYYY-MM-DD'
      });
    }

    if (inicio> fim) {
      return sendJson(res, 400, {
        error: 'A data inicial não pode ser posterior à data final'
      });
    }

    /*
     * Em produção, antes de gerar o relatório, também deve existir
     * uma camada de autenticação/autorização verificando se o usuário
     * autenticado pertence à empresa solicitada.
     *
     * Exemplo conceitual:
     *
     * if (!usuarioPertenceAEmpresa(req.user, companyId)) {
     *   return sendJson(res, 403, {
     *     error: 'Acesso negado'
     *   });
     * }
     */

    const relatorio = await gerarRelatorioFinanceiro(
      companyId,
      inicio,
      fim
    );

    return sendJson(res, 200, relatorio);

  }catch (error) {
    console.error('Erro ao gerar relatório:', error);

    return sendJson(res, 500, {
      error: 'Erro interno ao gerar o relatório'
    });
  }
}

const server = http.createServer(handleRequest);

server.listen(PORT, ()=> {
  console.log(`API executando em http://localhost:${PORT}`);
});