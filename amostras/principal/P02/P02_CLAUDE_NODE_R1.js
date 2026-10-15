/**
 * financialReport.routes.js
 *
 * Rota responsável por gerar e retornar o relatório financeiro consolidado
 * de uma empresa cliente (tenant) em uma plataforma SaaS multilocatária.
 *
 * Requisitos de segurança contemplados:
 *  - Isolamento de tenant: a empresa da rota (companyId) é sempre comparada
 *    com a empresa vinculada ao usuário autenticado (req.user.companyId).
 *    Nunca confiamos apenas no parâmetro de URL para decidir quais dados
 *    retornar — ele é validado contra o contexto de autenticação.
 *  - Toda consulta ao banco usa parâmetros (prepared statements), nunca
 *    concatenação de strings, prevenindo SQL Injection.
 *  - Validação de entrada (formato de datas, período, UUID da empresa).
 *  - Plano de assinatura ativo é verificado antes de gerar o relatório.
 *
 * Stack de exemplo: Express + node-postgres (pg). Adapte o acesso a dados
 * (dbPool) para o driver/ORM realmente usado no projeto.
 */

const express = require('express');
const { param, query, validationResult } = require('express-validator');

const router = express.Router();

/**
 * Middleware de autenticação (exemplo).
 * Espera-se que popule req.user com, no mínimo:
 *   { id, companyId, role }
 * Substitua pela implementação real (JWT, sessão, etc).
 */
const { authenticate } = require('../middlewares/authenticate');

/**
 * Middleware de autorização multi-tenant.
 * Garante que o usuário autenticado só possa solicitar relatórios
 * da própria empresa, mesmo que o companyId da URL seja manipulado.
 */
function ensureSameTenant(req, res, next) {
  const { companyId } = req.params;

  if (!req.user || !req.user.companyId) {
    return res.status(401).json({ error: 'Usuário não autenticado.' });
  }

  // Usuários com papel de "superadmin" da plataforma (suporte interno),
  // se existirem, poderiam ter uma exceção explícita aqui — nunca implícita.
  const isSameCompany = req.user.companyId === companyId;
  const isPlatformSupport = req.user.role === 'platform_support';

  if (!isSameCompany && !isPlatformSupport) {
    return res.status(403).json({
      error: 'Acesso negado: usuário não pertence a esta empresa.',
    });
  }

  next();
}

/**
 * Validações de entrada dos parâmetros da rota.
 */
const validateRequest = [
  param('companyId')
    .isUUID()
    .withMessage('companyId deve ser um UUID válido.'),
  query('startDate')
    .isISO8601()
    .withMessage('startDate deve estar no formato ISO 8601 (YYYY-MM-DD).'),
  query('endDate')
    .isISO8601()
    .withMessage('endDate deve estar no formato ISO 8601 (YYYY-MM-DD).'),
];

function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { startDate, endDate } = req.query;
  if (new Date(startDate) > new Date(endDate)) {
    return res.status(400).json({
      error: 'startDate não pode ser posterior a endDate.',
    });
  }

  // Limita o intervalo máximo consultável (ex.: 366 dias) para evitar
  // consultas custosas/abusivas em uma tabela compartilhada por tenants.
  const MAX_RANGE_DAYS = 366;
  const rangeInDays =
    (new Date(endDate) - new Date(startDate)) / (1000 * 60 * 60 * 24);
  if (rangeInDays > MAX_RANGE_DAYS) {
    return res.status(400).json({
      error: `O período consultado não pode exceder ${MAX_RANGE_DAYS} dias.`,
    });
  }

  next();
}

/**
 * Verifica se a empresa possui assinatura ativa antes de liberar o relatório.
 * Ajuste a tabela/coluna conforme seu schema real.
 */
async function ensureActiveSubscription(dbPool, companyId) {
  const { rows } = await dbPool.query(
    `SELECT status
       FROM subscriptions
      WHERE company_id = $1
      ORDER BY created_at DESC
      LIMIT 1`,
    [companyId]
  );

  return rows.length > 0 && rows[0].status === 'active';
}

/**
 * Consulta e consolida os dados financeiros do período.
 * Todas as tabelas são filtradas por company_id (isolamento de dados
 * a nível de query, reforçando o isolamento já feito na camada de auth).
 */
async function buildConsolidatedReport(dbPool, companyId, startDate, endDate) {
  const params = [companyId, startDate, endDate];

  const [revenueResult, expensesResult, invoicesResult] = await Promise.all([
    dbPool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total_revenue
         FROM revenues
        WHERE company_id = $1
          AND occurred_at BETWEEN $2 AND $3`,
      params
    ),
    dbPool.query(
      `SELECT category, COALESCE(SUM(amount), 0) AS total
         FROM expenses
        WHERE company_id = $1
          AND occurred_at BETWEEN $2 AND $3
        GROUP BY category
        ORDER BY total DESC`,
      params
    ),
    dbPool.query(
      `SELECT status, COUNT(*) AS count, COALESCE(SUM(amount), 0) AS total
         FROM invoices
        WHERE company_id = $1
          AND issued_at BETWEEN $2 AND $3
        GROUP BY status`,
      params
    ),
  ]);

  const totalRevenue = Number(revenueResult.rows[0].total_revenue);
  const expensesByCategory = expensesResult.rows.map((row) => ({
    category: row.category,
    total: Number(row.total),
  }));
  const totalExpenses = expensesByCategory.reduce(
    (sum, item) => sum + item.total,
    0
  );

  return {
    companyId,
    period: { startDate, endDate },
    summary: {
      totalRevenue,
      totalExpenses,
      netResult: Number((totalRevenue - totalExpenses).toFixed(2)),
    },
    expensesByCategory,
    invoices: invoicesResult.rows.map((row) => ({
      status: row.status,
      count: Number(row.count),
      total: Number(row.total),
    })),
    generatedAt: new Date().toISOString(),
  };
}

/**
 * GET /api/companies/:companyId/financial-report?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD
 */
module.exports = function createFinancialReportRouter(dbPool) {
  router.get(
    '/companies/:companyId/financial-report',
    authenticate,
    ensureSameTenant,
    validateRequest,
    handleValidationErrors,
    async (req, res) => {
      const { companyId } = req.params;
      const { startDate, endDate } = req.query;

      try {
        const hasActiveSubscription = await ensureActiveSubscription(
          dbPool,
          companyId
        );

        if (!hasActiveSubscription) {
          return res.status(402).json({
            error:
              'Empresa sem assinatura ativa. Relatório indisponível.',
          });
        }

        const report = await buildConsolidatedReport(
          dbPool,
          companyId,
          startDate,
          endDate
        );

        return res.status(200).json(report);
      } catch (error) {
        // Log estruturado real (winston/pino) substituiria o console.error.
        console.error('Erro ao gerar relatório financeiro:', error);
        return res.status(500).json({
          error: 'Erro interno ao gerar o relatório financeiro.',
        });
      }
    }
  );

  return router;
};