// routes/expenseApprovals.js
'use strict';

const express = require('express');
const { z } = require('zod');
const pool = require('../db/pool');                 // instância de pg.Pool
const { authenticate } = require('../middlewares/authenticate');
const { requireActiveSubscription } = require('../middlewares/subscription');

const router = express.Router();

const APPROVER_ROLES = new Set(['admin', 'finance_manager', 'manager']);

const paramsSchema = z.object({
  id: z.string().uuid(),
});

const bodySchema = z
  .object({
    comment: z.string().trim().max(500).optional(),
  })
  .strict();

router.post(
  '/expense-requests/:id/approve',
  authenticate,
  requireActiveSubscription, // bloqueia empresas com plano inativo/inadimplente
  async (req, res, next) => {
    // 1. Validação de entrada
    const params = paramsSchema.safeParse(req.params);
    const body = bodySchema.safeParse(req.body ?? {});
    if (!params.success || !body.success) {
      return res.status(400).json({ error: 'Requisição inválida.' });
    }

    const { id: requestId } = params.data;
    const { comment } = body.data;
    const { id: userId, companyId, role } = req.user;

    // 2. Autorização por papel
    if (!APPROVER_ROLES.has(role)) {
      return res.status(403).json({ error: 'Sem permissão para aprovar despesas.' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 3. Busca com isolamento por tenant + bloqueio da linha (evita aprovação concorrente)
      const { rows } = await client.query(
        `SELECT id, requester_id, status
           FROM expense_requests
          WHERE id = $1
            AND company_id = $2
          FOR UPDATE`,
        [requestId, companyId]
      );

      // Mesmo 404 para "não existe" e "pertence a outra empresa" (não vaza existência)
      if (rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Solicitação não encontrada.' });
      }

      const expense = rows[0];

      // 4. Segregação de funções: ninguém aprova a própria despesa
      if (expense.requester_id === userId) {
        await client.query('ROLLBACK');
        return res
          .status(403)
          .json({ error: 'Você não pode aprovar a sua própria solicitação.' });
      }

      // 5. Validação da máquina de estados
      if (expense.status !== 'pending') {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: `Solicitação não pode ser aprovada no estado atual (${expense.status}).`,
        });
      }

      // 6. Atualização (company_id repetido na cláusula como defesa em profundidade)
      const update = await client.query(
        `UPDATE expense_requests
            SET status      = 'approved',
                approved_by = $3,
                approved_at = NOW(),
                updated_at  = NOW()
          WHERE id = $1
            AND company_id = $2
            AND status = 'pending'
        RETURNING id, status, approved_by, approved_at`,
        [requestId, companyId, userId]
      );

      // 7. Trilha de auditoria
      await client.query(
        `INSERT INTO audit_logs
           (company_id, user_id, action, entity_type, entity_id, metadata, created_at)
         VALUES ($1, $2, 'expense_request.approved', 'expense_request', $3, $4, NOW())`,
        [companyId, userId, requestId, JSON.stringify({ comment: comment ?? null })]
      );

      await client.query('COMMIT');

      const approved = update.rows[0];
      return res.status(200).json({
        message: 'Solicitação de despesa aprovada com sucesso.',
        data: {
          id: approved.id,
          status: approved.status,
          approvedBy: approved.approved_by,
          approvedAt: approved.approved_at,
        },
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      return next(err); // handler global registra o erro e responde 500 genérico
    } finally {
      client.release();
    }
  }
);

module.exports = router;

// middlewares/subscription.js
const pool = require('../db/pool');

async function requireActiveSubscription(req, res, next) {
  try {
    const { rows } = await pool.query(
      `SELECT 1 FROM subscriptions
        WHERE company_id = $1
          AND status = 'active'
          AND (ends_at IS NULL OR ends_at > NOW())`,
      [req.user.companyId]
    );
    if (rows.length === 0) {
      return res.status(402).json({ error: 'Assinatura inativa.' });
    }
    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { requireActiveSubscription };