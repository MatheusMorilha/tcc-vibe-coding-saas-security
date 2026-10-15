const express = require('express');
const {Pool }= require('pg');

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

/**
 * GET /api/companies/:companyId/financial-report
 *
 * Query params:
 *   startDate=2026-01-01
 *   endDate=2026-01-31
 *
 * Exemplo:
 * GET /api/companies/123/financial-report?startDate=2026-01-01&endDate=2026-01-31
 */
app.get('/api/companies/:companyId/financial-report', async (req, res)=> {
  const {companyId }= req.params;
  const {startDate, endDate }= req.query;

  // Validação básica
  if (!/^\d+$/.test(companyId)) {
    return res.status(400).json({
      error: 'companyId inválido'
    });
  }

  if (!isValidDate(startDate)|| !isValidDate(endDate)) {
    return res.status(400).json({
      error: 'startDate e endDate devem estar no formato YYYY-MM-DD'
    });
  }

  if (startDate> endDate) {
    return res.status(400).json({
      error: 'startDate não pode ser posterior a endDate'
    });
  }

  const client = await pool.connect();

  try {
    /*
     * A autorização deve ocorrer antes de consultar os dados financeiros.
     *
     * req.user.companyId representa a empresa à qual o usuário autenticado
     * pertence. Nunca confie apenas no companyId enviado pela URL.
     */
    if (!req.user) {
      return res.status(401).json({
        error: 'Não autenticado'
      });
    }

    if (String(req.user.companyId)!== String(companyId)) {
      return res.status(403).json({
        error: 'Acesso negado'
      });
    }

    /*
     * Usamos parâmetros na query para evitar SQL injection.
     *
     * O filtro company_id é obrigatório: como todas as empresas compartilham
     * a mesma base, ele é o principal limite de isolamento dos dados.
     */
    const query = `
      SELECT
        COUNT(*) AS transaction_count,

        COALESCE(
          SUM(
            CASE
              WHEN type = 'income' THEN amount
              ELSE 0
            END
          ),
          0
        ) AS total_income,

        COALESCE(
          SUM(
            CASE
              WHEN type = 'expense' THEN amount
              ELSE 0
            END
          ),
          0
        ) AS total_expense,

        COALESCE(
          SUM(
            CASE
              WHEN type = 'income' THEN amount
              WHEN type = 'expense' THEN -amount
              ELSE 0
            END
          ),
          0
        ) AS net_result

      FROM financial_transactions
      WHERE company_id = $1
        AND transaction_date >= $2::date
        AND transaction_date < ($3::date + INTERVAL '1 day')
    `;

    const result = await client.query(query, [
      companyId,
      startDate,
      endDate
    ]);

    const report = result.rows[0];

    return res.status(200).json({
      companyId: Number(companyId),
      period: {
        startDate,
        endDate
      },
      totals: {
        transactions: Number(report.transaction_count),
        income: Number(report.total_income),
        expense: Number(report.total_expense),
        net: Number(report.net_result)
      }
    });
  }catch (error) {
    console.error('Erro ao gerar relatório financeiro:', error);

    return res.status(500).json({
      error: 'Não foi possível gerar o relatório financeiro'
    });
  }finally {
    client.release();
  }
});

function isValidDate(value) {
  if (typeof value!== 'string') {
    return false;
  }

  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return false;
  }

  const date = new Date(`${value}T00:00:00Z`);

  return !Number.isNaN(date.getTime())&&
    date.toISOString().slice(0, 10)=== value;
}

app.listen(process.env.PORT || 3000, ()=> {
  console.log('API iniciada');
});