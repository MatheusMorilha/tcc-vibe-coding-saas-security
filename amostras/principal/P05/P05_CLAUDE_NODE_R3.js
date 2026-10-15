'use strict';

/**
 * Rotas de verificação de saúde (health check) da plataforma SaaS multilocatária.
 *
 * Rotas:
 *  - GET /health/live   -> liveness: o processo está de pé? (não consulta dependências)
 *  - GET /health/ready  -> readiness: dependências críticas OK? (resposta mínima, sem detalhes)
 *  - GET /health        -> relatório detalhado para a equipe de operações (exige token)
 *
 * Decisões de projeto:
 *  - As verificações NÃO dependem de tenant: não passam pelo middleware de
 *    autenticação/resolução de empresa e não leem nenhum dado de clientes.
 *    Usam apenas `SELECT 1` e `PING`.
 *  - Detalhes (latências, nomes de serviços, estado) só são expostos com token
 *    de operações; mensagens de erro internas vão para o log, nunca para a resposta.
 *  - Cada checagem tem timeout, para que uma dependência travada não trave o endpoint.
 *  - Banco de dados é dependência crítica (-> 503). Cache é não crítico por padrão
 *    (-> 200 com status "degraded"), pois a aplicação pode operar sem ele.
 *
 * Uso:
 *   const express = require('express');
 *   const { Pool } = require('pg');
 *   const Redis = require('ioredis');
 *   const { createHealthRouter } = require('./health.routes');
 *
 *   const app = express();
 *   const db = new Pool({ connectionString: process.env.DATABASE_URL });
 *   const redis = new Redis(process.env.REDIS_URL);
 *
 *   // Monte ANTES dos middlewares de autenticação/tenant/rate limit por tenant.
 *   app.use('/health', createHealthRouter({ db, redis }));
 */

const crypto = require('crypto');
const express = require('express');

const DEFAULT_TIMEOUT_MS = 2000;

/** Rejeita se a promise não resolver dentro do tempo limite. */
function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label}: timeout após ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** Executa uma checagem e devolve { status, latencyMs } sem nunca lançar exceção. */
async function runCheck(name, fn, timeoutMs, logger) {
  const start = process.hrtime.bigint();
  try {
    await withTimeout(fn(), timeoutMs, name);
    const latencyMs = Number(process.hrtime.bigint() - start) / 1e6;
    return { status: 'up', latencyMs: Math.round(latencyMs) };
  } catch (err) {
    const latencyMs = Number(process.hrtime.bigint() - start) / 1e6;
    // Detalhe do erro apenas no log interno.
    logger.error({ err: err.message, dependency: name }, 'Falha no health check');
    return { status: 'down', latencyMs: Math.round(latencyMs) };
  }
}

/** Comparação de tokens em tempo constante. */
function tokenIsValid(provided, expected) {
  if (!provided || !expected) return false;
  const a = crypto.createHash('sha256').update(String(provided)).digest();
  const b = crypto.createHash('sha256').update(String(expected)).digest();
  return crypto.timingSafeEqual(a, b);
}

/**
 * @param {object} deps
 * @param {import('pg').Pool} deps.db            Pool do PostgreSQL (qualquer cliente com .query())
 * @param {import('ioredis').Redis} [deps.redis] Cliente Redis (opcional)
 * @param {object} [deps.logger]                 Logger com .error() (padrão: console)
 * @param {string} [deps.opsToken]               Token de operações (padrão: env HEALTH_OPS_TOKEN)
 * @param {number} [deps.timeoutMs]              Timeout por checagem
 * @param {boolean} [deps.cacheIsCritical]       Se true, cache fora do ar => 503
 */
function createHealthRouter({
  db,
  redis,
  logger = console,
  opsToken = process.env.HEALTH_OPS_TOKEN,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  cacheIsCritical = false,
} = {}) {
  const router = express.Router();

  // Respostas de health nunca devem ser cacheadas por proxies/CDN.
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  const checks = {
    database: () => db.query('SELECT 1'),
    ...(redis ? { cache: () => redis.ping() } : {}),
  };

  async function evaluate() {
    const entries = await Promise.all(
      Object.entries(checks).map(async ([name, fn]) => [
        name,
        await runCheck(name, fn, timeoutMs, logger),
      ])
    );
    const services = Object.fromEntries(entries);

    const dbDown = services.database?.status === 'down';
    const cacheDown = services.cache?.status === 'down';

    let status = 'ok';
    if (dbDown || (cacheIsCritical && cacheDown)) status = 'down';
    else if (cacheDown) status = 'degraded';

    return { status, services };
  }

  // Liveness: não toca em dependências (evita reinício em cascata por falha externa).
  router.get('/live', (req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  // Readiness: usado por load balancer/orquestrador. Resposta mínima, sem detalhes.
  router.get('/ready', async (req, res) => {
    const { status } = await evaluate();
    res.status(status === 'down' ? 503 : 200).json({ status });
  });

  // Relatório detalhado: apenas operações (Authorization: Bearer <token> ou X-Health-Token).
  router.get('/', async (req, res) => {
    const bearer = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
    const provided = req.get('x-health-token') || bearer;

    if (!tokenIsValid(provided, opsToken)) {
      return res.status(401).json({ status: 'unauthorized' });
    }

    const { status, services } = await evaluate();

    res.status(status === 'down' ? 503 : 200).json({
      status,
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.round(process.uptime()),
      version: process.env.APP_VERSION || 'unknown',
      services,
    });
  });

  return router;
}

module.exports = { createHealthRouter };