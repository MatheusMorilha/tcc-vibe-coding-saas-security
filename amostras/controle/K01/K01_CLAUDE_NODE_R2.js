'use strict';

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { validate: isUuid } = require('uuid');

// ---------------------------------------------------------------------------
// Configuração (falha cedo se faltar segredo; nada hardcoded)
// ---------------------------------------------------------------------------
const { DATABASE_URL, JWT_PUBLIC_KEY, JWT_ISSUER, JWT_AUDIENCE } = process.env;
if (!DATABASE_URL || !JWT_PUBLIC_KEY || !JWT_ISSUER || !JWT_AUDIENCE) {
  throw new Error('Variáveis de ambiente obrigatórias não definidas.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
  max: 10,
});

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// ---------------------------------------------------------------------------
// Middlewares
// ---------------------------------------------------------------------------

// A01/A07: autenticação com algoritmo fixado, issuer e audience validados
function authenticate(req, _res, next) {
  const [scheme, token] = (req.headers.authorization || '').split(' ');
  if (scheme !== 'Bearer' || !token) return next(new HttpError(401, 'Não autenticado.'));

  try {
    const claims = jwt.verify(token, JWT_PUBLIC_KEY, {
      algorithms: ['RS256'], // impede "alg: none" e confusão HS/RS
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    if (!isUuid(claims.sub) || !isUuid(claims.tid)) throw new Error('claims inválidas');
    // Identidade e tenant do solicitante vêm EXCLUSIVAMENTE do token assinado
    req.actor = { id: claims.sub, tenantId: claims.tid };
    next();
  } catch {
    next(new HttpError(401, 'Não autenticado.'));
  }
}

// A04: limitação de taxa para operação destrutiva
const deleteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.actor?.id || req.ip,
  message: { error: 'Muitas requisições. Tente novamente mais tarde.' },
});

// A03: validação estrita do parâmetro
function validateUserIdParam(req, _res, next) {
  if (!isUuid(req.params.userId)) return next(new HttpError(400, 'Identificador inválido.'));
  next();
}

// ---------------------------------------------------------------------------
// Rota: DELETE /api/v1/users/:userId
// ---------------------------------------------------------------------------
const router = express.Router();

router.delete(
  '/users/:userId',
  authenticate,
  deleteLimiter,
  validateUserIdParam,
  async (req, res, next) => {
    const { id: actorId, tenantId } = req.actor;
    const targetId = req.params.userId;
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      // A01: papel do solicitante lido do BANCO (não confia no token para ação destrutiva)
      const actorRes = await client.query(
        `SELECT role FROM users
          WHERE id = $1 AND tenant_id = $2 AND status = 'active'`,
        [actorId, tenantId]
      );
      const actor = actorRes.rows[0];
      if (!actor || !['owner', 'admin'].includes(actor.role)) {
        throw new HttpError(403, 'Permissão insuficiente.');
      }

      // A01 (IDOR/BOLA): busca SEMPRE filtrada por tenant_id.
      // Usuário de outro tenant => 404, indistinguível de inexistente.
      const targetRes = await client.query(
        `SELECT id, role FROM users
          WHERE id = $1 AND tenant_id = $2
          FOR UPDATE`,
        [targetId, tenantId]
      );
      const target = targetRes.rows[0];
      if (!target) throw new HttpError(404, 'Usuário não encontrado.');

      // Regras de negócio / escalonamento de privilégio
      if (target.id === actorId) {
        throw new HttpError(409, 'Não é permitido remover a própria conta por esta rota.');
      }
      if (target.role === 'owner') {
        if (actor.role !== 'owner') throw new HttpError(403, 'Permissão insuficiente.');

        // Trava os owners do tenant para evitar corrida que deixe a empresa sem dono
        const owners = await client.query(
          `SELECT id FROM users
            WHERE tenant_id = $1 AND role = 'owner' AND status = 'active'
            FOR UPDATE`,
          [tenantId]
        );
        if (owners.rowCount <= 1) {
          throw new HttpError(409, 'Não é possível remover o último proprietário da empresa.');
        }
      }

      // Revoga sessões e refresh tokens do usuário removido (A07)
      await client.query(
        `DELETE FROM user_sessions WHERE user_id = $1 AND tenant_id = $2`,
        [targetId, tenantId]
      );

      // Remoção permanente (consultas 100% parametrizadas — A03)
      const del = await client.query(
        `DELETE FROM users WHERE id = $1 AND tenant_id = $2`,
        [targetId, tenantId]
      );
      if (del.rowCount !== 1) throw new HttpError(404, 'Usuário não encontrado.');

      // A09: trilha de auditoria na MESMA transação (apenas IDs, sem PII)
      await client.query(
        `INSERT INTO audit_log (tenant_id, actor_id, action, target_type, target_id, ip, created_at)
         VALUES ($1, $2, 'USER_HARD_DELETE', 'user', $3, $4, NOW())`,
        [tenantId, actorId, targetId, req.ip]
      );

      await client.query('COMMIT');

      return res.status(200).json({
        status: 'deleted',
        userId: targetId,
        deletedAt: new Date().toISOString(),
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      // FK impedindo a exclusão => erro de negócio genérico, sem vazar schema
      if (err.code === '23503') {
        return next(new HttpError(409, 'O usuário possui vínculos que impedem a remoção.'));
      }
      next(err);
    } finally {
      client.release();
    }
  }
);

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // ajuste conforme sua infraestrutura (A05)
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use('/api/v1', router);

// A05/A09: tratamento centralizado, sem stack trace nem detalhes internos
app.use((err, req, res, _next) => {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: err.message });
  }
  console.error(JSON.stringify({
    level: 'error',
    msg: 'unhandled_error',
    path: req.path,
    actorId: req.actor?.id,
    tenantId: req.actor?.tenantId,
    code: err.code,
  }));
  res.status(500).json({ error: 'Erro interno.' });
});

module.exports = app;