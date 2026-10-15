'use strict';

/**
 * Plataforma SaaS multilocatária - Alteração de permissões + trilha de auditoria
 *
 * Dependências: npm i express pg jsonwebtoken
 *
 * Rotas:
 *   PUT /api/v1/users/:userId/permissions   -> altera permissões e audita
 *   GET /api/v1/audit-logs                  -> consulta a trilha (somente do tenant do solicitante)
 *
 * ---------------------------------------------------------------------------
 * MIGRAÇÃO SQL (PostgreSQL) - rode antes de subir a aplicação
 * ---------------------------------------------------------------------------
 *
 * ALTER TABLE users
 *   ADD COLUMN IF NOT EXISTS permissions text[] NOT NULL DEFAULT '{}',
 *   ADD COLUMN IF NOT EXISTS version integer NOT NULL DEFAULT 1,
 *   ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
 *
 * -- tenants deve ter: id uuid, subscription_status text, plan_features text[]
 *
 * CREATE TABLE audit_logs (
 *   id            bigserial PRIMARY KEY,
 *   tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
 *   actor_user_id uuid        NOT NULL,
 *   action        text        NOT NULL,
 *   entity_type   text        NOT NULL,
 *   entity_id     uuid        NOT NULL,
 *   before_state  jsonb,
 *   after_state   jsonb,
 *   metadata      jsonb       NOT NULL DEFAULT '{}',
 *   ip            inet,
 *   user_agent    text,
 *   request_id    text,
 *   created_at    timestamptz NOT NULL DEFAULT now()
 * );
 * CREATE INDEX audit_logs_tenant_idx        ON audit_logs (tenant_id, id DESC);
 * CREATE INDEX audit_logs_tenant_entity_idx ON audit_logs (tenant_id, entity_id, id DESC);
 * CREATE INDEX audit_logs_tenant_actor_idx  ON audit_logs (tenant_id, actor_user_id, id DESC);
 * CREATE INDEX audit_logs_tenant_time_idx   ON audit_logs (tenant_id, created_at DESC);
 *
 * -- Trilha append-only: ninguém (nem a aplicação) altera ou apaga registros.
 * CREATE FUNCTION audit_logs_immutable() RETURNS trigger AS $$
 * BEGIN RAISE EXCEPTION 'audit_logs é append-only'; END; $$ LANGUAGE plpgsql;
 * CREATE TRIGGER audit_logs_no_change BEFORE UPDATE OR DELETE ON audit_logs
 *   FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
 * CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
 *   FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_immutable();
 * REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM app_role;
 *
 * -- Recomendado (defesa em profundidade): Row Level Security por tenant em
 * -- users e audit_logs, usando SET LOCAL app.tenant_id a cada transação.
 * ---------------------------------------------------------------------------
 */

const express = require('express');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET não configurado');

// ---------------------------------------------------------------------------
// Catálogo de permissões (whitelist). Nunca aceite strings arbitrárias.
// ---------------------------------------------------------------------------
const PERMISSION_CATALOG = new Set([
  'users:read',
  'users:write',
  'users:manage_permissions',
  'billing:read',
  'billing:manage',
  'invoices:read',
  'invoices:write',
  'reports:read',
  'audit:read',
]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ACTIVE_SUBSCRIPTIONS = new Set(['active', 'trialing']);

// ---------------------------------------------------------------------------
// Erros
// ---------------------------------------------------------------------------
class AppError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------------------------------------------------------------------------
// Middlewares
// ---------------------------------------------------------------------------
function requestContext(req, _res, next) {
  const incoming = req.get('x-request-id');
  req.requestId = incoming && /^[\w-]{8,64}$/.test(incoming) ? incoming : crypto.randomUUID();
  next();
}

/**
 * Autentica o JWT e confirma no banco que o usuário existe, está ativo e
 * pertence ao tenant declarado no token. O tenant usado em TODA query vem
 * daqui (req.auth.tenantId) - jamais do body, query string ou params.
 */
const authenticate = asyncHandler(async (req, _res, next) => {
  const header = req.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) throw new AppError(401, 'UNAUTHENTICATED', 'Token ausente');

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    throw new AppError(401, 'UNAUTHENTICATED', 'Token inválido ou expirado');
  }
  if (!UUID_RE.test(payload.sub || '') || !UUID_RE.test(payload.tid || '')) {
    throw new AppError(401, 'UNAUTHENTICATED', 'Token malformado');
  }

  const { rows } = await pool.query(
    `SELECT u.id, u.role, u.status, u.permissions,
            t.subscription_status, t.plan_features
       FROM users u
       JOIN tenants t ON t.id = u.tenant_id
      WHERE u.id = $1 AND u.tenant_id = $2`,
    [payload.sub, payload.tid]
  );
  const row = rows[0];
  if (!row || row.status !== 'active') {
    throw new AppError(401, 'UNAUTHENTICATED', 'Usuário inválido');
  }
  if (!ACTIVE_SUBSCRIPTIONS.has(row.subscription_status)) {
    throw new AppError(402, 'SUBSCRIPTION_INACTIVE', 'Assinatura da empresa não está ativa');
  }

  req.auth = {
    userId: row.id,
    tenantId: payload.tid,
    role: row.role,
    permissions: row.permissions,
    planFeatures: row.plan_features || [],
  };
  next();
});

const hasPermission = (actor, permission) =>
  actor.role === 'owner' || actor.permissions.includes(permission);

const requirePermission = (permission) => (req, _res, next) => {
  if (!hasPermission(req.auth, permission)) {
    return next(new AppError(403, 'FORBIDDEN', 'Permissão insuficiente'));
  }
  next();
};

// ---------------------------------------------------------------------------
// Validação
// ---------------------------------------------------------------------------
function validatePermissionsBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new AppError(400, 'INVALID_BODY', 'Corpo da requisição inválido');
  }
  const { permissions, expectedVersion, reason } = body;

  if (!Array.isArray(permissions) || permissions.length > PERMISSION_CATALOG.size) {
    throw new AppError(400, 'INVALID_PERMISSIONS', '"permissions" deve ser uma lista');
  }
  const unique = [...new Set(permissions)];
  const unknown = unique.filter((p) => typeof p !== 'string' || !PERMISSION_CATALOG.has(p));
  if (unknown.length) {
    throw new AppError(400, 'UNKNOWN_PERMISSION', 'Permissões desconhecidas', {
      unknown: unknown.map(String).slice(0, 20),
    });
  }

  if (expectedVersion !== undefined && !Number.isInteger(expectedVersion)) {
    throw new AppError(400, 'INVALID_VERSION', '"expectedVersion" deve ser inteiro');
  }
  if (reason !== undefined && (typeof reason !== 'string' || reason.length > 500)) {
    throw new AppError(400, 'INVALID_REASON', '"reason" deve ser texto de até 500 caracteres');
  }

  return { permissions: unique.sort(), expectedVersion, reason: reason?.trim() || null };
}

// ---------------------------------------------------------------------------
// Auditoria: sempre chamada dentro da MESMA transação da alteração.
// Se o registro de auditoria falhar, a alteração inteira é desfeita.
// ---------------------------------------------------------------------------
async function writeAudit(client, entry) {
  const { rows } = await client.query(
    `INSERT INTO audit_logs
       (tenant_id, actor_user_id, action, entity_type, entity_id,
        before_state, after_state, metadata, ip, user_agent, request_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
     RETURNING id, created_at`,
    [
      entry.tenantId,
      entry.actorUserId,
      entry.action,
      entry.entityType,
      entry.entityId,
      JSON.stringify(entry.before),
      JSON.stringify(entry.after),
      JSON.stringify(entry.metadata || {}),
      entry.ip || null,
      entry.userAgent ? entry.userAgent.slice(0, 512) : null,
      entry.requestId,
    ]
  );
  return rows[0];
}

// ---------------------------------------------------------------------------
// PUT /api/v1/users/:userId/permissions
// ---------------------------------------------------------------------------
async function updateUserPermissions(req, res) {
  const { tenantId, userId: actorId } = req.auth;
  const targetId = req.params.userId;

  if (!UUID_RE.test(targetId)) throw new AppError(400, 'INVALID_USER_ID', 'ID de usuário inválido');
  if (!req.auth.planFeatures.includes('granular_permissions')) {
    throw new AppError(403, 'PLAN_FEATURE_UNAVAILABLE', 'O plano atual não inclui permissões granulares');
  }

  const { permissions: desired, expectedVersion, reason } = validatePermissionsBody(req.body);

  if (targetId === actorId) {
    throw new AppError(403, 'SELF_MODIFICATION', 'Não é permitido alterar as próprias permissões');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Serializa alterações de permissão dentro do tenant: a autorização do ator
    // abaixo é lida de forma consistente e evita corridas (ex.: dois admins se
    // rebaixando ao mesmo tempo).
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`perm:${tenantId}`]);

    // Reavalia o ator DENTRO da transação (pode ter sido rebaixado há instantes).
    const actorRes = await client.query(
      `SELECT role, status, permissions FROM users WHERE id = $1 AND tenant_id = $2`,
      [actorId, tenantId]
    );
    const actor = actorRes.rows[0];
    if (!actor || actor.status !== 'active' || !hasPermission(actor, 'users:manage_permissions')) {
      throw new AppError(403, 'FORBIDDEN', 'Permissão insuficiente');
    }

    // Filtra SEMPRE por tenant_id. Usuário de outro tenant => 404 (não vaza existência).
    const targetRes = await client.query(
      `SELECT id, role, status, permissions, version
         FROM users
        WHERE id = $1 AND tenant_id = $2
        FOR UPDATE`,
      [targetId, tenantId]
    );
    const target = targetRes.rows[0];
    if (!target) throw new AppError(404, 'USER_NOT_FOUND', 'Usuário não encontrado');

    if (target.role === 'owner') {
      throw new AppError(403, 'OWNER_IMMUTABLE', 'As permissões do proprietário não podem ser alteradas por esta rota');
    }
    if (expectedVersion !== undefined && expectedVersion !== target.version) {
      throw new AppError(409, 'VERSION_CONFLICT', 'O usuário foi modificado por outra requisição', {
        currentVersion: target.version,
      });
    }

    const current = [...target.permissions].sort();
    const added = desired.filter((p) => !current.includes(p));
    const removed = current.filter((p) => !desired.includes(p));

    // Sem mudança real: nada a gravar, nada a auditar.
    if (added.length === 0 && removed.length === 0) {
      await client.query('ROLLBACK');
      return res.status(200).json({
        userId: target.id,
        permissions: current,
        version: target.version,
        changed: false,
      });
    }

    // Anti-escalação de privilégio: só concede/revoga o que o próprio ator possui.
    const actorCanManage = (p) => actor.role === 'owner' || actor.permissions.includes(p);
    const forbidden = [...added, ...removed].filter((p) => !actorCanManage(p));
    if (forbidden.length) {
      throw new AppError(403, 'PRIVILEGE_ESCALATION', 'Você não pode conceder ou revogar permissões que não possui', {
        permissions: forbidden,
      });
    }

    const updated = await client.query(
      `UPDATE users
          SET permissions = $1, version = version + 1, updated_at = now()
        WHERE id = $2 AND tenant_id = $3
        RETURNING version`,
      [desired, targetId, tenantId]
    );

    const audit = await writeAudit(client, {
      tenantId,
      actorUserId: actorId,
      action: 'user.permissions.updated',
      entityType: 'user',
      entityId: targetId,
      before: { permissions: current },
      after: { permissions: desired },
      metadata: { added, removed, reason, targetRole: target.role },
      ip: req.ip,
      userAgent: req.get('user-agent'),
      requestId: req.requestId,
    });

    await client.query('COMMIT');

    return res.status(200).json({
      userId: targetId,
      permissions: desired,
      version: updated.rows[0].version,
      changed: true,
      added,
      removed,
      auditId: String(audit.id),
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// ---------------------------------------------------------------------------
// GET /api/v1/audit-logs
// Filtros: entityId, actorId, action, from, to, limit (1-100), cursor
// Paginação por keyset (id decrescente): estável e eficiente em tabelas grandes.
// ---------------------------------------------------------------------------
async function listAuditLogs(req, res) {
  const { tenantId } = req.auth;
  const { entityId, actorId, action, from, to, cursor } = req.query;

  const where = ['tenant_id = $1'];
  const params = [tenantId];
  const add = (sql, value) => {
    params.push(value);
    where.push(sql.replace('?', `$${params.length}`));
  };

  if (entityId !== undefined) {
    if (!UUID_RE.test(entityId)) throw new AppError(400, 'INVALID_FILTER', 'entityId inválido');
    add('entity_id = ?', entityId);
  }
  if (actorId !== undefined) {
    if (!UUID_RE.test(actorId)) throw new AppError(400, 'INVALID_FILTER', 'actorId inválido');
    add('actor_user_id = ?', actorId);
  }
  if (action !== undefined) {
    if (typeof action !== 'string' || !/^[a-z_.]{1,64}$/.test(action)) {
      throw new AppError(400, 'INVALID_FILTER', 'action inválida');
    }
    add('action = ?', action);
  }
  for (const [name, value, op] of [['from', from, '>='], ['to', to, '<=']]) {
    if (value === undefined) continue;
    const d = new Date(value);
    if (typeof value !== 'string' || Number.isNaN(d.getTime())) {
      throw new AppError(400, 'INVALID_FILTER', `${name} deve ser uma data ISO-8601`);
    }
    add(`created_at ${op} ?`, d.toISOString());
  }
  if (cursor !== undefined) {
    if (typeof cursor !== 'string' || !/^\d{1,18}$/.test(cursor)) {
      throw new AppError(400, 'INVALID_CURSOR', 'cursor inválido');
    }
    add('id < ?', cursor);
  }

  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
  params.push(limit + 1);

  const { rows } = await pool.query(
    `SELECT id, actor_user_id, action, entity_type, entity_id,
            before_state, after_state, metadata, ip, user_agent, request_id, created_at
       FROM audit_logs
      WHERE ${where.join(' AND ')}
      ORDER BY id DESC
      LIMIT $${params.length}`,
    params
  );

  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;

  res.status(200).json({
    data: page.map((r) => ({
      id: String(r.id),
      actorUserId: r.actor_user_id,
      action: r.action,
      entityType: r.entity_type,
      entityId: r.entity_id,
      before: r.before_state,
      after: r.after_state,
      metadata: r.metadata,
      ip: r.ip,
      userAgent: r.user_agent,
      requestId: r.request_id,
      createdAt: r.created_at,
    })),
    nextCursor: hasMore ? String(page[page.length - 1].id) : null,
  });
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();
app.set('trust proxy', 1); // ajuste conforme sua infraestrutura (LB/proxy reverso)
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use(requestContext);

app.put(
  '/api/v1/users/:userId/permissions',
  authenticate,
  requirePermission('users:manage_permissions'),
  asyncHandler(updateUserPermissions)
);

app.get(
  '/api/v1/audit-logs',
  authenticate,
  requirePermission('audit:read'),
  asyncHandler(listAuditLogs)
);

// Tratamento centralizado: não vaza detalhes internos.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  if (err instanceof AppError) {
    return res.status(err.status).json({
      error: { code: err.code, message: err.message, details: err.details, requestId: req.requestId },
    });
  }
  if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
    return res.status(400).json({
      error: { code: 'INVALID_BODY', message: 'JSON inválido ou grande demais', requestId: req.requestId },
    });
  }
  console.error({ requestId: req.requestId, err });
  res.status(500).json({
    error: { code: 'INTERNAL_ERROR', message: 'Erro interno', requestId: req.requestId },
  });
});

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`API ouvindo na porta ${port}`));
}

module.exports = { app, updateUserPermissions, listAuditLogs };