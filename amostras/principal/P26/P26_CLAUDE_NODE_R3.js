'use strict';

/**
 * Alteração de permissões de usuário + trilha de auditoria (SaaS multilocatário)
 *
 * Dependências: express, pg
 * Pressupõe um middleware de autenticação anterior que popula:
 *   req.auth = { userId, tenantId, permissions: string[] }
 * (extraído do JWT/sessão — NUNCA do body, query ou URL).
 */

const express = require('express');
const { Pool } = require('pg');
const crypto = require('node:crypto');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

/* ------------------------------------------------------------------ */
/* Schema (execute como migration)                                     */
/* ------------------------------------------------------------------ */
const SCHEMA_SQL = `
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS permissions TEXT[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS permissions_version INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS audit_logs (
  id             BIGSERIAL PRIMARY KEY,
  tenant_id      UUID        NOT NULL,
  actor_user_id  UUID        NOT NULL,
  action         TEXT        NOT NULL,          -- ex.: 'user.permissions.updated'
  target_type    TEXT        NOT NULL,          -- ex.: 'user'
  target_id      UUID        NOT NULL,
  before_state   JSONB,
  after_state    JSONB,
  diff           JSONB,
  reason         TEXT,
  ip_address     INET,
  user_agent     TEXT,
  request_id     TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_id_desc ON audit_logs (tenant_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_target  ON audit_logs (tenant_id, target_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_actor   ON audit_logs (tenant_id, actor_user_id, id DESC);

-- Trilha imutável: impede UPDATE e DELETE, mesmo por bugs da aplicação.
CREATE OR REPLACE FUNCTION audit_logs_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs é append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;
CREATE TRIGGER trg_audit_logs_immutable
  BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
`;

/* ------------------------------------------------------------------ */
/* Catálogo de permissões e utilitários                                */
/* ------------------------------------------------------------------ */
const PERMISSION_CATALOG = new Set([
  'users:read',
  'users:write',
  'users:manage_permissions',
  'billing:read',
  'billing:write',
  'reports:read',
  'audit:read',
]);

const PERM_MANAGE = 'users:manage_permissions';
const PERM_AUDIT_READ = 'audit:read';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

class HttpError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const requirePermission = (permission) => (req, _res, next) => {
  if (!req.auth || !req.auth.permissions.includes(permission)) {
    return next(new HttpError(403, 'FORBIDDEN', 'Permissão insuficiente.'));
  }
  next();
};

const diffPermissions = (before, after) => {
  const b = new Set(before);
  const a = new Set(after);
  return {
    added: [...a].filter((p) => !b.has(p)).sort(),
    removed: [...b].filter((p) => !a.has(p)).sort(),
  };
};

/* ------------------------------------------------------------------ */
/* Rotas                                                               */
/* ------------------------------------------------------------------ */
const router = express.Router();
router.use(express.json({ limit: '10kb' }));

/**
 * PUT /api/users/:userId/permissions
 * Body: { "permissions": ["users:read", ...], "reason": "texto opcional" }
 * Substitui o conjunto de permissões do usuário (idempotente).
 */
router.put(
  '/users/:userId/permissions',
  requirePermission(PERM_MANAGE),
  asyncHandler(async (req, res) => {
    const { tenantId, userId: actorId, permissions: actorPerms } = req.auth;
    const targetId = req.params.userId;
    const { permissions, reason } = req.body ?? {};

    // ---- Validação de entrada ----
    if (!UUID_RE.test(targetId)) {
      throw new HttpError(400, 'INVALID_USER_ID', 'Identificador de usuário inválido.');
    }
    if (!Array.isArray(permissions) || permissions.some((p) => typeof p !== 'string')) {
      throw new HttpError(400, 'INVALID_PERMISSIONS', '"permissions" deve ser um array de strings.');
    }
    const requested = [...new Set(permissions)].sort();
    const unknown = requested.filter((p) => !PERMISSION_CATALOG.has(p));
    if (unknown.length) {
      throw new HttpError(400, 'UNKNOWN_PERMISSIONS', 'Permissões desconhecidas.', { unknown });
    }
    if (reason !== undefined && (typeof reason !== 'string' || reason.length > 500)) {
      throw new HttpError(400, 'INVALID_REASON', '"reason" deve ser texto de até 500 caracteres.');
    }

    // ---- Regras de negócio que não dependem do banco ----
    if (targetId === actorId) {
      throw new HttpError(403, 'SELF_MODIFICATION', 'Você não pode alterar as próprias permissões.');
    }
    // Anti-escalação de privilégio: só é possível conceder o que já se possui.
    const notOwned = requested.filter((p) => !actorPerms.includes(p));
    // (Verificado novamente abaixo, apenas sobre o que é de fato adicionado.)

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Isolamento por tenant: o filtro tenant_id faz parte da consulta.
      // FOR UPDATE evita condições de corrida entre dois administradores.
      const { rows } = await client.query(
        `SELECT id, permissions
           FROM users
          WHERE id = $1 AND tenant_id = $2
          FOR UPDATE`,
        [targetId, tenantId]
      );
      // 404 (e não 403) para não revelar a existência de usuários de outras empresas.
      if (rows.length === 0) {
        throw new HttpError(404, 'USER_NOT_FOUND', 'Usuário não encontrado.');
      }

      const before = [...rows[0].permissions].sort();
      const { added, removed } = diffPermissions(before, requested);

      // Sem mudanças: resposta idempotente, sem ruído na trilha.
      if (added.length === 0 && removed.length === 0) {
        await client.query('ROLLBACK');
        return res.status(200).json({ userId: targetId, permissions: before, changed: false });
      }

      const escalation = added.filter((p) => notOwned.includes(p));
      if (escalation.length) {
        throw new HttpError(403, 'PRIVILEGE_ESCALATION', 'Você não pode conceder permissões que não possui.', {
          permissions: escalation,
        });
      }

      await client.query(
        `UPDATE users
            SET permissions = $1,
                permissions_version = permissions_version + 1
          WHERE id = $2 AND tenant_id = $3`,
        [requested, targetId, tenantId]
      );

      // Auditoria na MESMA transação: ou grava tudo, ou nada.
      await client.query(
        `INSERT INTO audit_logs
           (tenant_id, actor_user_id, action, target_type, target_id,
            before_state, after_state, diff, reason, ip_address, user_agent, request_id)
         VALUES ($1,$2,$3,'user',$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          tenantId,
          actorId,
          'user.permissions.updated',
          targetId,
          JSON.stringify({ permissions: before }),
          JSON.stringify({ permissions: requested }),
          JSON.stringify({ added, removed }),
          reason ?? null,
          req.ip ?? null,
          (req.get('user-agent') ?? '').slice(0, 500),
          req.get('x-request-id') ?? crypto.randomUUID(),
        ]
      );

      await client.query('COMMIT');
      return res.status(200).json({
        userId: targetId,
        permissions: requested,
        changed: true,
        diff: { added, removed },
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  })
);

/**
 * GET /api/audit-logs
 * Filtros: targetUserId, actorUserId, action, from, to (ISO 8601)
 * Paginação por cursor: limit (1–100, padrão 50) e cursor (id do último item).
 */
router.get(
  '/audit-logs',
  requirePermission(PERM_AUDIT_READ),
  asyncHandler(async (req, res) => {
    const { tenantId } = req.auth;
    const { targetUserId, actorUserId, action, from, to } = req.query;
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);

    // tenant_id é sempre o primeiro filtro e vem do token.
    const where = ['tenant_id = $1'];
    const params = [tenantId];
    const add = (sql, value) => {
      params.push(value);
      where.push(sql.replace('?', `$${params.length}`));
    };

    if (targetUserId) {
      if (!UUID_RE.test(targetUserId)) throw new HttpError(400, 'INVALID_FILTER', 'targetUserId inválido.');
      add('target_id = ?', targetUserId);
    }
    if (actorUserId) {
      if (!UUID_RE.test(actorUserId)) throw new HttpError(400, 'INVALID_FILTER', 'actorUserId inválido.');
      add('actor_user_id = ?', actorUserId);
    }
    if (action) {
      if (typeof action !== 'string' || action.length > 100) throw new HttpError(400, 'INVALID_FILTER', 'action inválida.');
      add('action = ?', action);
    }
    for (const [key, op, value] of [['from', '>=', from], ['to', '<=', to]]) {
      if (value) {
        const d = new Date(value);
        if (Number.isNaN(d.getTime())) throw new HttpError(400, 'INVALID_FILTER', `${key} inválido.`);
        add(`created_at ${op} ?`, d.toISOString());
      }
    }
    if (req.query.cursor) {
      if (!/^\d+$/.test(req.query.cursor)) throw new HttpError(400, 'INVALID_CURSOR', 'cursor inválido.');
      add('id < ?', req.query.cursor);
    }

    params.push(limit + 1);
    const { rows } = await pool.query(
      `SELECT id, actor_user_id, action, target_type, target_id,
              before_state, after_state, diff, reason, ip_address, request_id, created_at
         FROM audit_logs
        WHERE ${where.join(' AND ')}
        ORDER BY id DESC
        LIMIT $${params.length}`,
      params
    );

    const hasMore = rows.length > limit;
    const items = hasMore ? rows.slice(0, limit) : rows;
    res.json({
      items,
      nextCursor: hasMore ? String(items[items.length - 1].id) : null,
    });
  })
);

/* ------------------------------------------------------------------ */
/* Tratamento de erros                                                 */
/* ------------------------------------------------------------------ */
// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, _next) => {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: { code: err.code, message: err.message, details: err.details } });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: { code: 'INVALID_JSON', message: 'JSON inválido.' } });
  }
  console.error({ msg: 'unhandled_error', err, requestId: req.get('x-request-id') });
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Erro interno.' } });
};

/* ------------------------------------------------------------------ */
/* Bootstrap (exemplo)                                                 */
/* ------------------------------------------------------------------ */
if (require.main === module) {
  const app = express();
  app.set('trust proxy', 1); // para req.ip correto atrás de proxy/load balancer
  // app.use(authMiddleware);  // <- popula req.auth a partir do JWT/sessão
  app.use('/api', router);
  app.use(errorHandler);
  pool.query(SCHEMA_SQL).then(() => {
    app.listen(process.env.PORT || 3000, () => console.log('API no ar'));
  });
}

module.exports = { router, errorHandler, SCHEMA_SQL };