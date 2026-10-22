// routes/expenseApprovals.js
'use strict';

const express = require('express');
const { z } = require('zod');
const { pool } = require('../db');                      // pg.Pool
const { authenticate } = require('../middlewares/auth'); // valida JWT e popula req.user
const { requireActiveSubscription } = require('../middlewares/subscription');

const router = express.Router();

// ---------- Validação de entrada ----------
const paramsSchema = z.object({
  id: z.string().uuid(),
});

const bodySchema = z.object({
  comment: z.string().trim().max(500).optional(),
});

// ---------- Rota ----------
// POST /api/v1/expense-requests/:id/approve
router.post(
  '/expense-requests/:id/approve',
  authenticate,
  requireActiveSubscription,
  async (req, res) => {
    const parsedParams = paramsSchema.safeParse(req.params);
    const parsedBody = bodySchema.safeParse(req.body ?? {});

    if (!parsedParams.success || !parsedBody.success) {
      return res.status(400).json({ error: 'Dados da requisição inválidos.' });
    }

    const { id: expenseId } = parsedParams.data;
    const { comment } = parsedBody.data;

    // IMPORTANTE: tenant e usuário vêm SEMPRE do token autenticado,
    // nunca do corpo, query string ou parâmetros da requisição.
    const { id: userId, companyId, role } = req.user;

    // Autorização por papel
    const approverRoles = ['admin', 'finance_manager', 'manager'];
    if (!approverRoles.includes(role)) {
      return res.status(403).json({ error: 'Sem permissão para aprovar despesas.' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Trava a linha e filtra pelo tenant. Se a despesa pertencer a outra
      // empresa, o resultado é idêntico a "não existe" (evita enumeração).
      const { rows } = await client.query(
        `SELECT id, requester_id, amount, status, approval_limit_required
           FROM expense_requests
          WHERE id = $1
            AND company_id = $2
          FOR UPDATE`,
        [expenseId, companyId]
      );

      if (rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Solicitação não encontrada.' });
      }

      const expense = rows[0];

      // Segregação de funções: ninguém aprova a própria despesa
      if (expense.requester_id === userId) {
        await client.query('ROLLBACK');
        return res
          .status(403)
          .json({ error: 'Você não pode aprovar a sua própria solicitação.' });
      }

      // Transição de estado válida somente a partir de "pending"
      if (expense.status !== 'pending') {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: `Solicitação não pode ser aprovada no estado atual (${expense.status}).`,
        });
      }

      // Alçada de aprovação do usuário (quando aplicável)
      const limitResult = await client.query(
        `SELECT approval_limit
           FROM users
          WHERE id = $1
            AND company_id = $2
            AND active = true`,
        [userId, companyId]
      );

      if (limitResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'Usuário inativo ou inválido.' });
      }

      const approvalLimit = limitResult.rows[0].approval_limit; // null = sem limite
      if (approvalLimit !== null && Number(expense.amount) > Number(approvalLimit)) {
        await client.query('ROLLBACK');
        return res
          .status(403)
          .json({ error: 'Valor acima da sua alçada de aprovação.' });
      }

      // Atualização do estado (mantém o filtro de tenant por defesa em profundidade)
      const updated = await client.query(
        `UPDATE expense_requests
            SET status      = 'approved',
                approved_by = $1,
                approved_at = NOW(),
                updated_at  = NOW()
          WHERE id = $2
            AND company_id = $3
            AND status = 'pending'
        RETURNING id, status, approved_by, approved_at`,
        [userId, expenseId, companyId]
      );

      // Trilha de auditoria
      await client.query(
        `INSERT INTO audit_logs
           (company_id, user_id, entity, entity_id, action, details, ip, created_at)
         VALUES ($1, $2, 'expense_request', $3, 'approve', $4, $5, NOW())`,
        [
          companyId,
          userId,
          expenseId,
          JSON.stringify({ comment: comment ?? null, previous_status: 'pending' }),
          req.ip,
        ]
      );

      await client.query('COMMIT');

      const result = updated.rows[0];
      return res.status(200).json({
        message: 'Solicitação de despesa aprovada com sucesso.',
        data: {
          id: result.id,
          status: result.status,
          approvedBy: result.approved_by,
          approvedAt: result.approved_at,
        },
      });
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (_) {
        /* ignora falha no rollback */
      }
      console.error('[expense-approve] erro:', {
        expenseId,
        companyId,
        message: err.message,
      });
      return res.status(500).json({ error: 'Erro interno ao processar a aprovação.' });
    } finally {
      client.release();
    }
  }
);

module.exports = router;

// middlewares/subscription.js
'use strict';
const { pool } = require('../db');

async function requireActiveSubscription(req, res, next) {
  try {
    const { rows } = await pool.query(
      `SELECT 1
         FROM subscriptions
        WHERE company_id = $1
          AND status = 'active'
          AND (expires_at IS NULL OR expires_at > NOW())
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

module.exports = { requireActiveSubscription };