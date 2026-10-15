'use strict';

const express = require('express');
const { Pool } = require('pg');

const pool = new Pool(); // configuração via variáveis de ambiente PG*
const router = express.Router();

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const APPROVER_ROLES = new Set(['admin', 'finance_manager', 'manager']);

/**
 * Pressupõe um middleware de autenticação anterior (JWT/sessão) que popula:
 *   req.auth = { userId, tenantId, roles: ['manager', ...] }
 * O tenantId vem SEMPRE do token validado, nunca de body/query/params.
 */

// Verifica se o plano da empresa está ativo (consulta no servidor, nunca confia no cliente)
async function requireActiveSubscription(req, res, next) {
  try {
    const { rows } = await pool.query(
      `SELECT 1 FROM subscriptions
        WHERE tenant_id = $1
          AND status IN ('active', 'trialing')
          AND (current_period_end IS NULL OR current_period_end > now())
        LIMIT 1`,
      [req.auth.tenantId]
    );
    if (rows.length === 0) {
      return res.status(402).json({
        error: 'subscription_inactive',
        message: 'A assinatura da empresa não está ativa.',
      });
    }
    next();
  } catch (err) {
    next(err);
  }
}

function requireApproverRole(req, res, next) {
  const allowed = (req.auth.roles || []).some((r) => APPROVER_ROLES.has(r));
  if (!allowed) {
    return res.status(403).json({
      error: 'forbidden',
      message: 'Você não tem permissão para aprovar despesas.',
    });
  }
  next();
}

/**
 * POST /api/v1/expense-requests/:id/approve
 * Body (opcional): { "comment": "string até 500 caracteres" }
 */
router.post(
  '/expense-requests/:id/approve',
  requireActiveSubscription,
  requireApproverRole,
  async (req, res, next) => {
    const { id } = req.params;
    const { userId, tenantId } = req.auth;
    const comment =
      typeof req.body?.comment === 'string' ? req.body.comment.trim().slice(0, 500) : null;

    if (!UUID_RE.test(id)) {
      return res.status(400).json({ error: 'invalid_id', message: 'Identificador inválido.' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Trava a linha e filtra por tenant: evita acesso entre empresas e corridas (dupla aprovação)
      const { rows } = await client.query(
        `SELECT id, requester_id, status, amount
           FROM expense_requests
          WHERE id = $1 AND tenant_id = $2
          FOR UPDATE`,
        [id, tenantId]
      );

      // 404 também para registros de outra empresa (não revela existência)
      if (rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'not_found', message: 'Solicitação não encontrada.' });
      }

      const expense = rows[0];

      // Segregação de funções: ninguém aprova a própria despesa
      if (expense.requester_id === userId) {
        await client.query('ROLLBACK');
        return res.status(403).json({
          error: 'self_approval_forbidden',
          message: 'Você não pode aprovar a sua própria solicitação.',
        });
      }

      // Máquina de estados: só pendentes podem ser aprovadas
      if (expense.status !== 'pending') {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'invalid_state',
          message: `Solicitação não pode ser aprovada: status atual é "${expense.status}".`,
        });
      }

      // Alçada do aprovador (limite de valor), validada no mesmo tenant
      const { rows: approverRows } = await client.query(
        `SELECT approval_limit FROM users
          WHERE id = $1 AND tenant_id = $2 AND is_active = true`,
        [userId, tenantId]
      );
      if (approverRows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'forbidden', message: 'Usuário inválido ou inativo.' });
      }
      const limit = approverRows[0].approval_limit;
      if (limit !== null && Number(expense.amount) > Number(limit)) {
        await client.query('ROLLBACK');
        return res.status(403).json({
          error: 'approval_limit_exceeded',
          message: 'O valor excede a sua alçada de aprovação.',
        });
      }

      // Atualização condicionada ao estado e ao tenant (defesa em profundidade)
      const { rows: updated } = await client.query(
        `UPDATE expense_requests
            SET status = 'approved',
                approved_by = $3,
                approved_at = now(),
                approval_comment = $4,
                updated_at = now()
          WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
          RETURNING id, status, approved_by, approved_at`,
        [id, tenantId, userId, comment]
      );

      if (updated.length === 0) {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'conflict', message: 'A solicitação foi alterada.' });
      }

      // Trilha de auditoria
      await client.query(
        `INSERT INTO audit_logs (tenant_id, actor_id, action, entity_type, entity_id, metadata, ip, created_at)
         VALUES ($1, $2, 'expense_request.approved', 'expense_request', $3, $4, $5, now())`,
        [tenantId, userId, id, JSON.stringify({ comment, amount: expense.amount }), req.ip]
      );

      await client.query('COMMIT');

      const result = updated[0];
      return res.status(200).json({
        success: true,
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
      return next(err);
    } finally {
      client.release();
    }
  }
);

module.exports = router;

/*
 * Uso:
 *   app.use(express.json({ limit: '10kb' }));
 *   app.use('/api/v1', authenticate, expenseRouter);
 *
 * Reforço opcional no banco (PostgreSQL Row-Level Security):
 *   ALTER TABLE expense_requests ENABLE ROW LEVEL SECURITY;
 *   CREATE POLICY tenant_isolation ON expense_requests
 *     USING (tenant_id = current_setting('app.tenant_id')::uuid);
 */