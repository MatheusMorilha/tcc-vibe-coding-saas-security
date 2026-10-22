// src/routes/expenseRequests.js
'use strict';

const express = require('express');
const { Pool } = require('pg');

const router = express.Router();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const APPROVER_ROLES = new Set(['admin', 'approver']);

// ---------- Middlewares ----------

// Pressupõe que um middleware de autenticação anterior (JWT/sessão) popula
// req.user = { id, companyId, role } a partir de um token VERIFICADO.
function requireAuth(req, res, next) {
  if (!req.user?.id || !req.user?.companyId) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  next();
}

function requireRole(roles) {
  return (req, res, next) => {
    if (!roles.has(req.user.role)) {
      return res.status(403).json({ error: 'Sem permissão para aprovar despesas.' });
    }
    next();
  };
}

async function requireActiveSubscription(req, res, next) {
  try {
    const { rows } = await pool.query(
      `SELECT 1
         FROM subscriptions
        WHERE company_id = $1
          AND status = 'active'
          AND (ends_at IS NULL OR ends_at > now())
        LIMIT 1`,
      [req.user.companyId]
    );
    if (rows.length === 0) {
      return res.status(402).json({ error: 'Assinatura inativa ou expirada.' });
    }
    next();
  } catch (err) {
    next(err);
  }
}

// ---------- Rota ----------

router.post(
  '/expense-requests/:id/approve',
  requireAuth,
  requireRole(APPROVER_ROLES),
  requireActiveSubscription,
  async (req, res, next) => {
    const { id } = req.params;
    const { id: approverId, companyId } = req.user;

    if (!UUID_RE.test(id)) {
      return res.status(400).json({ error: 'ID da solicitação inválido.' });
    }

    // Comentário opcional, com limite de tamanho
    const comment =
      typeof req.body?.comment === 'string' ? req.body.comment.trim().slice(0, 500) : null;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Transição atômica: só aprova se for da empresa, estiver pendente
      // e o solicitante for diferente do aprovador.
      const { rows, rowCount } = await client.query(
        `UPDATE expense_requests
            SET status = 'APPROVED',
                approved_by = $1,
                approved_at = now(),
                approval_comment = $2,
                updated_at = now()
          WHERE id = $3
            AND company_id = $4
            AND status = 'PENDING'
            AND requester_id <> $1
        RETURNING id, status, approved_by, approved_at, amount, currency`,
        [approverId, comment, id, companyId]
      );

      if (rowCount === 0) {
        // Diagnóstico para devolver o erro correto (ainda filtrando por tenant)
        const { rows: current } = await client.query(
          `SELECT status, requester_id
             FROM expense_requests
            WHERE id = $1 AND company_id = $2`,
          [id, companyId]
        );
        await client.query('ROLLBACK');

        if (current.length === 0) {
          return res.status(404).json({ error: 'Solicitação não encontrada.' });
        }
        if (current[0].requester_id === approverId) {
          return res
            .status(403)
            .json({ error: 'Você não pode aprovar a sua própria solicitação.' });
        }
        return res.status(409).json({
          error: `Solicitação não pode ser aprovada no estado atual (${current[0].status}).`,
        });
      }

      // Trilha de auditoria na mesma transação
      await client.query(
        `INSERT INTO audit_logs
           (company_id, user_id, action, entity, entity_id, metadata, ip, created_at)
         VALUES ($1, $2, 'EXPENSE_APPROVED', 'expense_request', $3, $4, $5, now())`,
        [companyId, approverId, id, JSON.stringify({ comment }), req.ip]
      );

      await client.query('COMMIT');

      return res.status(200).json({
        message: 'Solicitação de despesa aprovada com sucesso.',
        data: rows[0],
      });
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch (_) { /* ignora */ }
      next(err);
    } finally {
      client.release();
    }
  }
);

module.exports = router;

// src/app.js
const express = require('express');
const authMiddleware = require('./middlewares/auth'); // valida JWT e preenche req.user
const expenseRoutes = require('./routes/expenseRequests');

const app = express();
app.use(express.json({ limit: '10kb' }));
app.use('/api/v1', authMiddleware, expenseRoutes);

// Handler de erro: não vaza detalhes internos
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Erro interno do servidor.' });
});

module.exports = app;