'use strict';

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');
const { z } = require('zod');

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// A conexão deve usar TLS e credenciais vindas de variáveis de ambiente/secret manager.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
});

/* ------------------------------------------------------------------ */
/* Middlewares                                                         */
/* ------------------------------------------------------------------ */

// Correlaciona requisições e logs sem expor detalhes internos ao cliente.
app.use((req, _res, next) => {
  req.id = crypto.randomUUID();
  next();
});

// A01/A07: autenticação. O tenant e o papel vêm SEMPRE do token validado,
// nunca de parâmetros enviados pelo cliente.
function authenticate(req, res, next) {
  const header = req.get('authorization') || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_PUBLIC_KEY, {
      algorithms: ['RS256'],            // evita "alg: none" e confusão de algoritmos
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    });
    if (!payload.sub || !payload.tenant_id || !payload.role) {
      return res.status(401).json({ error: 'Não autenticado.' });
    }
    req.auth = { userId: payload.sub, tenantId: payload.tenant_id, role: payload.role };
    return next();
  } catch {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
}

// A01: autorização por papel (deny by default).
const requireRole = (...allowed) => (req, res, next) =>
  allowed.includes(req.auth.role)
    ? next()
    : res.status(403).json({ error: 'Acesso negado.' });

// A04/A07: limita abuso de operações destrutivas.
const destructiveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  keyGenerator: (req) => `${req.auth?.tenantId}:${req.auth?.userId}`,
  standardHeaders: true,
  legacyHeaders: false,
});

/* ------------------------------------------------------------------ */
/* Validação de entrada (A03)                                          */
/* ------------------------------------------------------------------ */

const paramsSchema = z.object({ id: z.string().uuid() }).strict();

/* ------------------------------------------------------------------ */
/* Rota                                                                */
/* ------------------------------------------------------------------ */

const ROLE_RANK = { member: 1, admin: 2, owner: 3 };

app.delete(
  '/api/v1/users/:id',
  authenticate,
  requireRole('owner', 'admin'),
  destructiveLimiter,
  async (req, res, next) => {
    const parsed = paramsSchema.safeParse(req.params);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Identificador de usuário inválido.' });
    }

    const targetId = parsed.data.id;
    const { tenantId, userId: actorId, role: actorRole } = req.auth;

    // Regra de negócio: ninguém exclui a si mesmo por esta rota.
    if (targetId === actorId) {
      return res.status(409).json({ error: 'Não é possível excluir o próprio usuário por esta rota.' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // A01 (IDOR/multitenancy): o filtro por tenant_id é obrigatório em TODA query.
      // FOR UPDATE evita condições de corrida (ex.: dois owners se excluindo ao mesmo tempo).
      const { rows } = await client.query(
        'SELECT id, role FROM users WHERE id = $1 AND tenant_id = $2 FOR UPDATE',
        [targetId, tenantId]
      );

      // Usuário inexistente OU de outro tenant: mesma resposta (não vaza existência).
      if (rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Usuário não encontrado.' });
      }

      const target = rows[0];

      // A01: hierarquia — só pode excluir quem tem papel estritamente inferior,
      // exceto owner, que pode excluir outro owner (respeitando a regra abaixo).
      const canDelete =
        actorRole === 'owner' || ROLE_RANK[target.role] < ROLE_RANK[actorRole];
      if (!canDelete) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'Acesso negado.' });
      }

      // Integridade: a empresa nunca pode ficar sem owner.
      if (target.role === 'owner') {
        const owners = await client.query(
          "SELECT id FROM users WHERE tenant_id = $1 AND role = 'owner' FOR UPDATE",
          [tenantId]
        );
        if (owners.rowCount <= 1) {
          await client.query('ROLLBACK');
          return res.status(409).json({ error: 'A empresa deve manter ao menos um owner.' });
        }
      }

      // Revoga sessões/tokens para o acesso cessar imediatamente.
      await client.query(
        'DELETE FROM refresh_tokens WHERE user_id = $1 AND tenant_id = $2',
        [targetId, tenantId]
      );

      // Exclusão permanente (dados dependentes devem ter FK com ON DELETE CASCADE/SET NULL
      // definidos no schema, ou ser tratados aqui na mesma transação).
      const del = await client.query(
        'DELETE FROM users WHERE id = $1 AND tenant_id = $2',
        [targetId, tenantId]
      );

      // A09: trilha de auditoria na mesma transação, sem dados pessoais (apenas IDs).
      await client.query(
        `INSERT INTO audit_logs (tenant_id, actor_id, action, target_id, ip, request_id)
         VALUES ($1, $2, 'USER_DELETED', $3, $4, $5)`,
        [tenantId, actorId, targetId, req.ip, req.id]
      );

      await client.query('COMMIT');

      return res.status(200).json({
        message: 'Usuário removido permanentemente.',
        id: targetId,
        deleted: del.rowCount === 1,
        deletedAt: new Date().toISOString(),
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      return next(err);
    } finally {
      client.release();
    }
  }
);

/* ------------------------------------------------------------------ */
/* Tratamento de erros (A05/A09): sem stack trace nem detalhes ao cliente */
/* ------------------------------------------------------------------ */

app.use((err, req, res, _next) => {
  console.error(JSON.stringify({
    level: 'error',
    requestId: req.id,
    route: 'DELETE /api/v1/users/:id',
    message: err.message,
  }));
  res.status(500).json({ error: 'Erro interno.', requestId: req.id });
});

module.exports = app;