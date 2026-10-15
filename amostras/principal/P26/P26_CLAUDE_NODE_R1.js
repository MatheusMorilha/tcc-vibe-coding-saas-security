'use strict';

/**
 * Alteração de permissões de usuário + trilha de auditoria (SaaS multilocatário)
 *
 * Dependências: express, pg
 * Pressuposto: um middleware anterior (JWT/sessão) popula req.auth = { userId, tenantId }.
 * O tenantId vem SEMPRE do token autenticado, nunca do corpo, query ou URL.
 */

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

/* ------------------------------------------------------------------ */
/* 1. Migração (rode uma vez)                                          */
/* ------------------------------------------------------------------ */

const MIGRATION_SQL = `
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS permissions text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS permissions_version integer NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS audit_logs (
  id             bigserial PRIMARY KEY,
  tenant_id      uuid        NOT NULL REFERENCES tenants(id),
  actor_user_id  uuid        NOT NULL,
  action         text        NOT NULL,
  entity_type    text        NOT NULL,
  entity_id      uuid        NOT NULL,
  before_state   jsonb,
  after_state    jsonb,
  reason         text,
  request_id     text,
  ip_address     inet,
  user_agent     text,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_logs_tenant_idx
  ON audit_logs (tenant_id, id DESC);
CREATE INDEX IF NOT EXISTS audit_logs_tenant_entity_idx
  ON audit_logs (tenant_id, entity_type, entity_id, id DESC);

-- Trilha append-only: bloqueia UPDATE e DELETE, inclusive para a role da aplicação.
CREATE OR REPLACE FUNCTION audit_logs_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs é imutável';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs;
CREATE TRIGGER audit_logs_no_update
  BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
`;

async function migrate() {
  await pool.query(MIGRATION_SQL);
}

/* ------------------------------------------------------------------ */
/* 2. Catálogo de permissões (whitelist) e regras de plano             */
/* ------------------------------------------------------------------ */

const PLAN_RANK = { basic: 1, pro: 2, enterprise: 3 };

// permissão -> plano mínimo que a disponibiliza
const PERMISSION_CATALOG = {
  'users:read': 'basic',
  'users:manage_permissions': 'basic',
  'invoices:read': 'basic',
  'invoices:write': 'basic',
  'reports:read': 'pro',
  'reports:export': 'pro',
  'audit:read': 'pro',
  'integrations:manage': 'enterprise',
};

const MANAGER_PERMISSION = 'users:manage_permissions';
const MAX_PERMISSIONS = 50;

/* ------------------------------------------------------------------ */
/* 3. Utilitários                                                      */
/* ------------------------------------------------------------------ */

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const sorted = (arr) => [...arr].sort();
const diff = (a, b) => a.filter((x) => !b.includes(x));

function validateBody(body) {
  const { permissions, reason, expectedVersion } = body ?? {};

  if (!Array.isArray(permissions) || permissions.length > MAX_PERMISSIONS) {
    throw new HttpError(400, 'INVALID_PERMISSIONS', 'permissions deve ser um array válido.');
  }
  if (!permissions.every((p) => typeof p === 'string' && Object.hasOwn(PERMISSION_CATALOG, p))) {
    throw new HttpError(400, 'UNKNOWN_PERMISSION', 'Há permissões inexistentes no catálogo.');
  }
  if (typeof reason !== 'string' || reason.trim().length < 5 || reason.length > 500) {
    throw new HttpError(400, 'INVALID_REASON', 'reason é obrigatório (5 a 500 caracteres).');
  }
  if (!Number.isInteger(expectedVersion) || expectedVersion < 1) {
    throw new HttpError(400, 'INVALID_VERSION', 'expectedVersion deve ser um inteiro positivo.');
  }

  return {
    permissions: sorted([...new Set(permissions)]),
    reason: reason.trim(),
    expectedVersion,
  };
}

/** Grava o evento de auditoria usando o MESMO client da transação (atomicidade). */
async function writeAudit(client, entry) {
  await client.query(
    `INSERT INTO audit_logs
       (tenant_id, actor_user_id, action, entity_type, entity_id,
        before_state, after_state, reason, request_id, ip_address, user_agent)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      entry.tenantId,
      entry.actorId,
      entry.action,
      entry.entityType,
      entry.entityId,
      JSON.stringify(entry.before),
      JSON.stringify(entry.after),
      entry.reason,
      entry.requestId,
      entry.ip,
      entry.userAgent?.slice(0, 300) ?? null,
    ]
  );
}

/** Verifica se o usuário autenticado possui determinada permissão (dados frescos do banco). */
async function loadActor(client, tenantId, userId) {
  const { rows } = await client.query(
    `SELECT id, role, permissions
       FROM users
      WHERE id = $1 AND tenant_id = $2 AND active = true`,
    [userId, tenantId]
  );
  return rows[0] ?? null;
}

/* ------------------------------------------------------------------ */
/* 4. Rotas                                                            */
/* ------------------------------------------------------------------ */

const router = express.Router();

/**
 * PUT /api/v1/users/:userId/permissions
 * Body: { permissions: string[], reason: string, expectedVersion: number }
 */
router.put('/users/:userId/permissions', async (req, res, next) => {
  const { userId: actorId, tenantId } = req.auth;
  const targetId = req.params.userId;
  const requestId = req.headers['x-request-id'] || crypto.randomUUID();

  let client;
  try {
    if (!UUID_RE.test(targetId)) {
      throw new HttpError(400, 'INVALID_USER_ID', 'Identificador de usuário inválido.');
    }
    const { permissions: newPerms, reason, expectedVersion } = validateBody(req.body);

    client = await pool.connect();
    await client.query('BEGIN');

    // Serializa alterações de permissão dentro do mesmo tenant
    // (evita corrida na regra do "último administrador").
    const { rows: tenantRows } = await client.query(
      `SELECT t.id, t.subscription_status, p.code AS plan
         FROM tenants t
         JOIN plans p ON p.id = t.plan_id
        WHERE t.id = $1
        FOR UPDATE OF t`,
      [tenantId]
    );
    const tenant = tenantRows[0];
    if (!tenant) throw new HttpError(403, 'TENANT_NOT_FOUND', 'Empresa não encontrada.');
    if (tenant.subscription_status !== 'active') {
      throw new HttpError(402, 'SUBSCRIPTION_INACTIVE', 'Assinatura inativa.');
    }

    // Autorização do ator (lida do banco, não do token, para evitar permissões obsoletas)
    const actor = await loadActor(client, tenantId, actorId);
    if (!actor || (actor.role !== 'owner' && !actor.permissions.includes(MANAGER_PERMISSION))) {
      throw new HttpError(403, 'FORBIDDEN', 'Sem permissão para gerenciar permissões.');
    }

    // Alvo restrito ao tenant. Se for de outro tenant, responde 404 (não vaza existência).
    const { rows: targetRows } = await client.query(
      `SELECT id, role, permissions, permissions_version
         FROM users
        WHERE id = $1 AND tenant_id = $2 AND active = true
        FOR UPDATE`,
      [targetId, tenantId]
    );
    const target = targetRows[0];
    if (!target) throw new HttpError(404, 'USER_NOT_FOUND', 'Usuário não encontrado.');

    if (target.id === actor.id) {
      throw new HttpError(403, 'SELF_MODIFICATION', 'Não é permitido alterar as próprias permissões.');
    }
    if (target.role === 'owner' && actor.role !== 'owner') {
      throw new HttpError(403, 'OWNER_PROTECTED', 'Apenas o proprietário altera outro proprietário.');
    }
    if (target.permissions_version !== expectedVersion) {
      throw new HttpError(409, 'VERSION_CONFLICT', 'Os dados foram alterados por outra requisição. Recarregue.');
    }

    // Permissões devem estar disponíveis no plano atual da empresa
    const planRank = PLAN_RANK[tenant.plan] ?? 0;
    const blocked = newPerms.filter((p) => PLAN_RANK[PERMISSION_CATALOG[p]] > planRank);
    if (blocked.length) {
      throw new HttpError(403, 'PLAN_RESTRICTION', `Permissões indisponíveis no plano atual: ${blocked.join(', ')}`);
    }

    const before = sorted(target.permissions);
    const granted = diff(newPerms, before);
    const revoked = diff(before, newPerms);

    // Sem mudança: nada a gravar
    if (!granted.length && !revoked.length) {
      await client.query('ROLLBACK');
      return res.status(200).json({
        userId: target.id, permissions: before, version: target.permissions_version, changed: false,
      });
    }

    // Anti-escalonamento de privilégio: só concede/revoga o que o próprio ator possui
    if (actor.role !== 'owner') {
      const forbidden = [...granted, ...revoked].filter((p) => !actor.permissions.includes(p));
      if (forbidden.length) {
        throw new HttpError(403, 'PRIVILEGE_ESCALATION', `Você não pode conceder/revogar: ${forbidden.join(', ')}`);
      }
    }

    // Preserva ao menos um gestor de permissões ativo no tenant
    if (revoked.includes(MANAGER_PERMISSION) && target.role !== 'owner') {
      const { rows } = await client.query(
        `SELECT count(*)::int AS n
           FROM users
          WHERE tenant_id = $1 AND active = true AND id <> $2
            AND (role = 'owner' OR $3 = ANY(permissions))`,
        [tenantId, target.id, MANAGER_PERMISSION]
      );
      if (rows[0].n === 0) {
        throw new HttpError(409, 'LAST_MANAGER', 'A empresa precisa manter ao menos um gestor de permissões.');
      }
    }

    // Atualização (tenant_id repetido no WHERE como defesa em profundidade)
    const { rows: updated } = await client.query(
      `UPDATE users
          SET permissions = $1,
              permissions_version = permissions_version + 1
        WHERE id = $2 AND tenant_id = $3 AND permissions_version = $4
        RETURNING permissions, permissions_version`,
      [newPerms, target.id, tenantId, expectedVersion]
    );
    if (!updated[0]) throw new HttpError(409, 'VERSION_CONFLICT', 'Conflito de versão.');

    // Auditoria na mesma transação: se falhar, a alteração é desfeita
    await writeAudit(client, {
      tenantId,
      actorId: actor.id,
      action: 'user.permissions.updated',
      entityType: 'user',
      entityId: target.id,
      before: { permissions: before, version: target.permissions_version },
      after: {
        permissions: updated[0].permissions,
        version: updated[0].permissions_version,
        granted,
        revoked,
      },
      reason,
      requestId,
      ip: req.ip,
      userAgent: req.get('user-agent'),
    });

    await client.query('COMMIT');

    return res.status(200).json({
      userId: target.id,
      permissions: updated[0].permissions,
      version: updated[0].permissions_version,
      changed: true,
      granted,
      revoked,
    });
  } catch (err) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    return next(err);
  } finally {
    if (client) client.release();
  }
});

/**
 * GET /api/v1/audit-logs
 * Query: entityId, actorId, action, from, to, limit (1-100), cursor
 * Resposta paginada por cursor (id decrescente).
 */
router.get('/audit-logs', async (req, res, next) => {
  try {
    const { userId, tenantId } = req.auth;

    const actor = await loadActor(pool, tenantId, userId);
    if (!actor || (actor.role !== 'owner' && !actor.permissions.includes('audit:read'))) {
      throw new HttpError(403, 'FORBIDDEN', 'Sem permissão para consultar a auditoria.');
    }

    const { entityId, actorId, action, from, to } = req.query;
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
    const cursor = req.query.cursor ? parseInt(req.query.cursor, 10) : null;

    for (const v of [entityId, actorId]) {
      if (v !== undefined && !UUID_RE.test(String(v))) {
        throw new HttpError(400, 'INVALID_FILTER', 'Filtro de identificador inválido.');
      }
    }
    for (const d of [from, to]) {
      if (d !== undefined && Number.isNaN(Date.parse(d))) {
        throw new HttpError(400, 'INVALID_DATE', 'Data inválida (use ISO 8601).');
      }
    }
    if (req.query.cursor && !Number.isInteger(cursor)) {
      throw new HttpError(400, 'INVALID_CURSOR', 'Cursor inválido.');
    }

    // tenant_id é sempre o primeiro filtro e vem do token
    const where = ['tenant_id = $1'];
    const params = [tenantId];
    const add = (sql, value) => { params.push(value); where.push(sql.replace('?', `$${params.length}`)); };

    if (entityId) add('entity_id = ?', entityId);
    if (actorId) add('actor_user_id = ?', actorId);
    if (action) add('action = ?', String(action).slice(0, 100));
    if (from) add('created_at >= ?', from);
    if (to) add('created_at <= ?', to);
    if (cursor) add('id < ?', cursor);

    params.push(limit + 1);
    const { rows } = await pool.query(
      `SELECT id, actor_user_id, action, entity_type, entity_id,
              before_state, after_state, reason, request_id, created_at
         FROM audit_logs
        WHERE ${where.join(' AND ')}
        ORDER BY id DESC
        LIMIT $${params.length}`,
      params
    );

    const hasMore = rows.length > limit;
    const items = hasMore ? rows.slice(0, limit) : rows;

    res.json({ items, nextCursor: hasMore ? items[items.length - 1].id : null });
  } catch (err) {
    next(err);
  }
});

/* ------------------------------------------------------------------ */
/* 5. Bootstrap e tratamento de erros                                  */
/* ------------------------------------------------------------------ */

function errorHandler(err, req, res, _next) {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: err.code, message: err.message });
  }
  console.error({ msg: 'erro não tratado', requestId: req.headers['x-request-id'], err });
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Erro interno.' });
}

module.exports = { router, errorHandler, migrate };

/*
Exemplo de uso:

const app = express();
app.set('trust proxy', 1);                    // para req.ip correto atrás de proxy
app.use(express.json({ limit: '10kb' }));
app.use(authMiddleware);                      // define req.auth = { userId, tenantId }
app.use('/api/v1', rateLimiter, router);      // aplique rate limit nas rotas sensíveis
app.use(errorHandler);
app.listen(3000);
*/