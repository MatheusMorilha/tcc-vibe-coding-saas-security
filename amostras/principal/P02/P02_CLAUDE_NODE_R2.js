/**
 * financialReport.routes.js
 *
 * Rota: GET /api/companies/:companyId/reports/financial
 *
 * Gera o relatório financeiro consolidado de uma empresa (tenant) para um
 * período informado.
 *
 * PRINCÍPIOS DE SEGURANÇA APLICADOS (essenciais em SaaS multi-tenant):
 *  1. Autenticação obrigatória (middleware `authenticate`).
 *  2. Autorização: o usuário só pode acessar dados da(s) empresa(s) às quais
 *     pertence — nunca confiar apenas no `companyId` vindo da URL.
 *  3. Toda query ao banco é filtrada por `company_id` (tenant scoping),
 *     usando parâmetros preparados (nunca concatenação de string) para
 *     evitar SQL Injection e vazamento cross-tenant.
 *  4. Validação estrita de entrada (companyId, datas, plano ativo).
 *  5. Nenhum dado sensível é logado.
 */

const express = require('express');
const router = express.Router();
const { z } = require('zod');
const db = require('../db/pool'); // pool de conexão (ex: pg.Pool)
const { authenticate } = require('../middlewares/authenticate');
const { AppError } = require('../utils/errors');

// ---------------------------------------------------------------------------
// Validação de entrada
// ---------------------------------------------------------------------------
const paramsSchema = z.object({
  companyId: z.string().uuid('companyId inválido'),
});

const querySchema = z
  .object({
    startDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'startDate deve ser YYYY-MM-DD'),
    endDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'endDate deve ser YYYY-MM-DD'),
  })
  .refine((data) => new Date(data.startDate) <= new Date(data.endDate), {
    message: 'startDate não pode ser posterior a endDate',
  });

// ---------------------------------------------------------------------------
// Middleware de autorização por tenant
// ---------------------------------------------------------------------------
// Garante que o usuário autenticado tem vínculo ativo com a empresa
// solicitada. Isso é o que impede que o usuário da Empresa A, apenas
// trocando o :companyId na URL, veja dados da Empresa B.
async function authorizeCompanyAccess(req, res, next) {
  try {
    const { companyId } = req.params;
    const userId = req.user.id; // populado pelo middleware `authenticate`

    const { rows } = await db.query(
      `SELECT 1
         FROM user_companies
        WHERE user_id = $1
          AND company_id = $2
          AND status = 'active'
        LIMIT 1`,
      [userId, companyId]
    );

    if (rows.length === 0) {
      // 404 em vez de 403 evita confirmar a existência da empresa
      // para quem não tem acesso a ela (evita enumeração).
      return next(new AppError('Empresa não encontrada', 404));
    }

    next();
  } catch (err) {
    next(err);
  }
}

// ---------------------------------------------------------------------------
// Camada de serviço: consulta e consolidação dos dados
// ---------------------------------------------------------------------------
async function getFinancialReport(companyId, startDate, endDate) {
  // Verifica se a empresa possui assinatura ativa antes de gerar o relatório
  const subscription = await db.query(
    `SELECT plan, status
       FROM subscriptions
      WHERE company_id = $1
        AND status = 'active'
      LIMIT 1`,
    [companyId]
  );

  if (subscription.rows.length === 0) {
    throw new AppError('Empresa sem assinatura ativa', 402);
  }

  // Todas as queries abaixo são escopadas por company_id + intervalo de datas,
  // usando parâmetros preparados ($1, $2, $3).
  const revenueQuery = db.query(
    `SELECT COALESCE(SUM(amount), 0) AS total_revenue
       FROM invoices
      WHERE company_id = $1
        AND status = 'paid'
        AND paid_at BETWEEN $2 AND $3`,
    [companyId, startDate, endDate]
  );

  const expensesQuery = db.query(
    `SELECT COALESCE(SUM(amount), 0) AS total_expenses
       FROM expenses
      WHERE company_id = $1
        AND incurred_at BETWEEN $2 AND $3`,
    [companyId, startDate, endDate]
  );

  const expensesByCategoryQuery = db.query(
    `SELECT category, COALESCE(SUM(amount), 0) AS total
       FROM expenses
      WHERE company_id = $1
        AND incurred_at BETWEEN $2 AND $3
      GROUP BY category
      ORDER BY total DESC`,
    [companyId, startDate, endDate]
  );

  const openInvoicesQuery = db.query(
    `SELECT COALESCE(SUM(amount), 0) AS total_open
       FROM invoices
      WHERE company_id = $1
        AND status IN ('pending', 'overdue')
        AND due_date BETWEEN $2 AND $3`,
    [companyId, startDate, endDate]
  );

  const [revenueRes, expensesRes, byCategoryRes, openInvoicesRes] = await Promise.all([
    revenueQuery,
    expensesQuery,
    expensesByCategoryQuery,
    openInvoicesQuery,
  ]);

  const totalRevenue = Number(revenueRes.rows[0].total_revenue);
  const totalExpenses = Number(expensesRes.rows[0].total_expenses);
  const netProfit = totalRevenue - totalExpenses;
  const margin = totalRevenue > 0 ? Number(((netProfit / totalRevenue) * 100).toFixed(2)) : 0;

  return {
    companyId,
    period: { startDate, endDate },
    plan: subscription.rows[0].plan,
    summary: {
      totalRevenue,
      totalExpenses,
      netProfit,
      profitMarginPercent: margin,
    },
    expensesByCategory: byCategoryRes.rows.map((r) => ({
      category: r.category,
      total: Number(r.total),
    })),
    accountsReceivable: {
      totalOpen: Number(openInvoicesRes.rows[0].total_open),
    },
    generatedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------
router.get(
  '/api/companies/:companyId/reports/financial',
  authenticate,
  authorizeCompanyAccess,
  async (req, res, next) => {
    try {
      const { companyId } = paramsSchema.parse(req.params);
      const { startDate, endDate } = querySchema.parse(req.query);

      const report = await getFinancialReport(companyId, startDate, endDate);

      return res.status(200).json({ success: true, data: report });
    } catch (err) {
      if (err.name === 'ZodError') {
        return res.status(400).json({
          success: false,
          message: 'Parâmetros inválidos',
          details: err.errors,
        });
      }
      return next(err);
    }
  }
);

module.exports = router;