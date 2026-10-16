'use strict';

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// A conexão usa credenciais do ambiente, com um usuário de banco de privilégio mínimo.
// TLS é obrigatório em produção (A02).
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
});

const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY; // sem segredo fixo no código (A02/A07)
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ---------- Middlewares ----------

// Rastreabilidade de cada requisição (A09)
app.use((req, _res, next) => {
  req.id = crypto.randomUUID();
  next();
});

// Autenticação (A07): algoritmo fixado, issuer/audience validados, expiração obrigatória.
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  try {
    const payload = jwt.verify(token, JWT_PUBLIC_KEY, {
      algorithms: ['RS256'],
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    });
    // O tenant vem SEMPRE do token validado, nunca de body, query ou params (A01).
    req.auth = { userId: payload.sub, tenantId: payload.tenant_id, role: payload.role };
    if (!UUID_RE.test(req.auth.userId) || !UUID_RE.test(req.auth.tenantId)) {
      return res.status(401).json({ error: 'Não autenticado.' });
    }
    next();
  } catch {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
}

// Autorização por função (A01): apenas administradores do tenant.
function requireTenantAdmin(req, res, next) {
  if (req.auth.role !== 'tenant_admin') {
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  next();
}

// Limita abuso e automação (A04/A05)
const deleteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  keyGenerator: (req) => req.auth?.userId || req.ip,
  standardHeaders: true,
  legacyHeaders: false,
});

// ---------- Rota ----------

app.delete(
  '/api/v1/users/:id',
  authenticate,
  requireTenantAdmin,
  deleteLimiter,
  async (req, res, next) => {
    const targetId = req.params.id;
    const { userId: actorId, tenantId } = req.auth;

    // Validação de entrada (A03)
    if (!UUID_RE.test(targetId)) {
      return res.status(400).json({ error: 'Identificador inválido.' });
    }

    // Regra de negócio: o administrador não pode se excluir por esta rota.
    if (targetId === actorId) {
      return res.status(409).json({ error: 'Não é permitido excluir o próprio usuário.' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Busca escopada pelo tenant (A01 - BOLA/IDOR). Se o usuário pertencer a outra
      // empresa, o resultado é idêntico a "não existe" (evita enumeração entre tenants).
      // As consultas são parametrizadas (A03 - SQL Injection).
      const { rows } = await client.query(
        `SELECT id, role FROM users
          WHERE id = $1 AND tenant_id = $2
          FOR UPDATE`,
        [targetId, tenantId]
      );
      if (rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Usuário não encontrado.' });
      }

      // Impede que a empresa fique sem nenhum administrador (A04 - design seguro).
      if (rows[0].role === 'tenant_admin') {
        const admins = await client.query(
          `SELECT id FROM users
            WHERE tenant_id = $1 AND role = 'tenant_admin'
            FOR UPDATE`,
          [tenantId]
        );
        if (admins.rowCount <= 1) {
          await client.query('ROLLBACK');
          return res
            .status(409)
            .json({ error: 'Não é possível remover o último administrador da empresa.' });
        }
      }

      // Revoga sessões e tokens para o acesso cessar imediatamente (A07).
      await client.query(
        'DELETE FROM refresh_tokens WHERE user_id = $1 AND tenant_id = $2',
        [targetId, tenantId]
      );
      await client.query(
        'DELETE FROM sessions WHERE user_id = $1 AND tenant_id = $2',
        [targetId, tenantId]
      );

      // Exclusão permanente; o filtro de tenant é repetido como defesa em profundidade.
      const del = await client.query(
        'DELETE FROM users WHERE id = $1 AND tenant_id = $2',
        [targetId, tenantId]
      );

      // Auditoria imutável, sem dados pessoais do usuário removido (A09).
      await client.query(
        `INSERT INTO audit_log (tenant_id, actor_id, action, target_id, request_id, ip, created_at)
         VALUES ($1, $2, 'USER_HARD_DELETE', $3, $4, $5, NOW())`,
        [tenantId, actorId, targetId, req.id, req.ip]
      );

      await client.query('COMMIT');

      return res.status(200).json({
        status: 'success',
        message: 'Usuário removido permanentemente.',
        deletedUserId: targetId,
        deletedRows: del.rowCount,
        deletedAt: new Date().toISOString(),
      });
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* ignora */ }
      // 23503 = violação de chave estrangeira: há dados que dependem do usuário.
      if (err.code === '23503') {
        return res.status(409).json({
          error: 'O usuário possui registros vinculados e não pode ser removido.',
        });
      }
      return next(err);
    } finally {
      client.release();
    }
  }
);

// ---------- Tratamento de erros (A05/A09) ----------
// Nunca expõe stack trace, SQL ou detalhes internos ao cliente.
app.use((err, req, res, _next) => {
  console.error(
    JSON.stringify({
      level: 'error',
      requestId: req.id,
      path: req.path,
      code: err.code,
      message: err.message,
    })
  );
  res.status(500).json({ error: 'Erro interno.', requestId: req.id });
});

module.exports = app;