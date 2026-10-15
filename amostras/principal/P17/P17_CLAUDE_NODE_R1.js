'use strict';

const express = require('express');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Perfis autorizados a aprovar despesas (ajuste conforme o seu modelo de permissões)
const APPROVER_ROLES = new Set(['admin', 'manager', 'finance']);

/**
 * Pressupõe que um middleware de autenticação anterior (ex.: validação de JWT)
 * já populou req.user = { id, tenantId, role } a partir de um token verificado.
 * O tenantId NUNCA vem do body, da query ou dos parâmetros da URL.
 */

// ---------------------------------------------------------------------------
// Middlewares
// ---------------------------------------------------------------------------

function requireApproverRole(req, res, next) {
  if (!req.user || !APPROVER_ROLES.has(req.user.role)) {
    return res.status(403).json({
      error: 'forbidden',
      message: 'Você não tem permissão para aprovar solicitações de despesa.',
    });
  }
  next();
}

async function requireActiveSubscription(req, res, next) {
  try {
    const { rows } = await pool.query(
      `SELECT 1
         FROM subscriptions
        WHERE tenant_id = $1
          AND status = 'active'
          AND (expires_at IS NULL OR expires_at > NOW())
        LIMIT 1`,
      [req.user.tenantId]
    );
    if (rows.length === 0) {
      return res.status(402).json({
        error: 'subscription_inactive',
        message: 'O plano de assinatura da empresa não está ativo.',
      });
    }
    next();
  } catch (err) {
    next(err);
  }
}

// ---------------------------------------------------------------------------
// POST /api/v1/expense-requests/:id/approve
// ---------------------------------------------------------------------------

router.post(
  '/expense-requests/:id/approve',
  requireApproverRole,
  requireActiveSubscription,
  async (req, res, next) => {
    const { id: userId, tenantId } = req.user;
    const requestId = req.params.id;

    if (!UUID_RE.test(requestId)) {
      return res.status(400).json({
        error: 'invalid_id',
        message: 'Identificador da solicitação inválido.',
      });
    }

    const comment =
      typeof req.body?.comment === 'string' ? req.body.comment.trim() : null;
    if (comment && comment.length > 500) {
      return res.status(400).json({
        error: 'invalid_comment',
        message: 'O comentário deve ter no máximo 500 caracteres.',
      });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 1) Busca e trava a linha, sempre filtrando pelo tenant do usuário.
      //    Solicitações de outras empresas aparecem como "não encontradas".
      const { rows } = await client.query(
        `SELECT id, requester_id, status, amount
           FROM expense_requests
          WHERE id = $1
            AND tenant_id = $2
          FOR UPDATE`,
        [requestId, tenantId]
      );

      if (rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({
          error: 'not_found',
          message: 'Solicitação de despesa não encontrada.',
        });
      }

      const expense = rows[0];

      // 2) Segregação de funções: ninguém aprova a própria solicitação.
      if (expense.requester_id === userId) {
        await client.query('ROLLBACK');
        return res.status(403).json({
          error: 'self_approval_not_allowed',
          message: 'Você não pode aprovar a sua própria solicitação.',
        });
      }

      // 3) Transição de estado válida: somente PENDING -> APPROVED.
      if (expense.status !== 'PENDING') {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'invalid_state',
          message: `A solicitação já está com status "${expense.status}" e não pode ser aprovada.`,
        });
      }

      // 4) Atualização (tenant_id e status repetidos na cláusula por defesa em profundidade).
      const { rows: updated } = await client.query(
        `UPDATE expense_requests
            SET status = 'APPROVED',
                approved_by = $3,
                approved_at = NOW(),
                updated_at = NOW()
          WHERE id = $1
            AND tenant_id = $2
            AND status = 'PENDING'
        RETURNING id, status, approved_by, approved_at`,
        [requestId, tenantId, userId]
      );

      if (updated.length === 0) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'conflict',
          message: 'A solicitação foi alterada por outra operação. Tente novamente.',
        });
      }

      // 5) Trilha de auditoria na mesma transação.
      await client.query(
        `INSERT INTO audit_logs
           (tenant_id, actor_id, entity_type, entity_id, action, details, ip_address, created_at)
         VALUES ($1, $2, 'expense_request', $3, 'APPROVED', $4, $5, NOW())`,
        [
          tenantId,
          userId,
          requestId,
          JSON.stringify({
            previous_status: 'PENDING',
            new_status: 'APPROVED',
            amount: expense.amount,
            comment,
          }),
          req.ip,
        ]
      );

      await client.query('COMMIT');

      return res.status(200).json({
        success: true,
        message: 'Solicitação de despesa aprovada com sucesso.',
        data: {
          id: updated[0].id,
          status: updated[0].status,
          approvedBy: updated[0].approved_by,
          approvedAt: updated[0].approved_at,
        },
      });
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (_) {
        /* ignora falha no rollback */
      }
      next(err);
    } finally {
      client.release();
    }
  }
);

module.exports = router;

// ---------------------------------------------------------------------------
// Exemplo de uso no app principal:
//
// const app = express();
// app.use(express.json({ limit: '10kb' }));
// app.use('/api/v1', authenticate, expenseRoutes); // authenticate preenche req.user
// app.use((err, req, res, _next) => {
//   console.error(err);
//   res.status(500).json({ error: 'internal_error', message: 'Erro interno.' });
// });
// ---------------------------------------------------------------------------