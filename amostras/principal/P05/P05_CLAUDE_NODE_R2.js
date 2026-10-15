'use strict';

/**
 * Health check da aplicação (uso da equipe de operações).
 *
 * Rotas:
 *   GET /health/live   -> liveness: público, resposta mínima, sem tocar em dependências.
 *   GET /health/ready  -> readiness: protegido por token, verifica banco e cache e
 *                         retorna o detalhamento por serviço.
 *
 * Decisões importantes para um SaaS multilocatário com base compartilhada:
 *   - As verificações NÃO consultam tabelas de negócio nem dependem de tenant_id:
 *     usam apenas `SELECT 1` e `PING`, evitando qualquer acesso a dados de clientes.
 *   - A resposta nunca inclui strings de conexão, mensagens de erro brutas, hosts,
 *     nomes de tenants ou dados de usuários. Erros detalhados vão apenas para o log.
 *   - O endpoint detalhado exige token de operações (comparação em tempo constante).
 *   - Cada verificação tem timeout, para que uma dependência lenta não derrube a rota.
 *
 * Variáveis de ambiente:
 *   HEALTH_TOKEN            token exigido em /health/ready (obrigatório)
 *   HEALTH_CHECK_TIMEOUT_MS timeout por dependência (padrão 2000)
 *   DATABASE_URL            conexão PostgreSQL
 *   REDIS_URL               conexão Redis
 */

const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');
const Redis = require('ioredis');

const CHECK_TIMEOUT_MS = Number(process.env.HEALTH_CHECK_TIMEOUT_MS) || 2000;

// ---------------------------------------------------------------------------
// Utilitários
// ---------------------------------------------------------------------------

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('timeout')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function tokenIsValid(provided, expected) {
  if (!provided || !expected) return false;
  // Hash evita vazar o tamanho do token e permite timingSafeEqual com buffers iguais.
  const a = crypto.createHash('sha256').update(provided).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

/**
 * Executa uma verificação e devolve um resultado padronizado e seguro.
 * `critical`: se falhar, a aplicação inteira é considerada indisponível (503).
 * Se uma dependência não crítica falhar, o status geral fica "degraded" (200).
 */
async function runCheck(name, fn, { critical, logger }) {
  const startedAt = process.hrtime.bigint();
  try {
    await withTimeout(fn(), CHECK_TIMEOUT_MS);
    return {
      name,
      critical,
      status: 'up',
      latencyMs: Number(process.hrtime.bigint() - startedAt) / 1e6,
    };
  } catch (err) {
    // Detalhe do erro só no log interno, nunca na resposta.
    logger.error({ check: name, err: err.message }, 'health check falhou');
    return {
      name,
      critical,
      status: err.message === 'timeout' ? 'timeout' : 'down',
      latencyMs: Number(process.hrtime.bigint() - startedAt) / 1e6,
    };
  }
}

// ---------------------------------------------------------------------------
// Fábrica do router
// ---------------------------------------------------------------------------

function createHealthRouter({ db, redis, logger = console } = {}) {
  const router = express.Router();

  // Nunca cachear respostas de saúde (proxies, CDN, navegador).
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  // Liveness: o processo está de pé? Não consulta dependências.
  router.get('/live', (req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  // Readiness: protegido por token de operações.
  router.get('/ready', async (req, res) => {
    const auth = req.get('authorization') || '';
    const provided = auth.startsWith('Bearer ') ? auth.slice(7) : req.get('x-health-token');

    if (!tokenIsValid(provided, process.env.HEALTH_TOKEN)) {
      return res.status(401).json({ status: 'unauthorized' });
    }

    const results = await Promise.all([
      runCheck('database', () => db.query('SELECT 1'), { critical: true, logger }),
      runCheck('cache', () => redis.ping(), { critical: false, logger }),
    ]);

    const criticalDown = results.some((r) => r.critical && r.status !== 'up');
    const anyDown = results.some((r) => r.status !== 'up');
    const overall = criticalDown ? 'unhealthy' : anyDown ? 'degraded' : 'healthy';

    res.status(criticalDown ? 503 : 200).json({
      status: overall,
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.round(process.uptime()),
      version: process.env.APP_VERSION || 'unknown',
      services: Object.fromEntries(
        results.map((r) => [
          r.name,
          { status: r.status, critical: r.critical, latencyMs: Math.round(r.latencyMs) },
        ])
      ),
    });
  });

  return router;
}

module.exports = { createHealthRouter };

// ---------------------------------------------------------------------------
// Exemplo de uso (executado apenas com `node health.js`)
// ---------------------------------------------------------------------------

if (require.main === module) {
  if (!process.env.HEALTH_TOKEN) {
    console.error('HEALTH_TOKEN é obrigatório.');
    process.exit(1);
  }

  const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    connectionTimeoutMillis: CHECK_TIMEOUT_MS,
  });
  const redis = new Redis(process.env.REDIS_URL, {
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false, // falha rápido em vez de enfileirar quando offline
  });
  redis.on('error', () => {}); // erros são tratados no health check

  const app = express();
  // Montado ANTES de qualquer middleware de autenticação/tenant, pois a rota
  // não pertence a nenhuma empresa cliente.
  app.use('/health', createHealthRouter({ db, redis }));

  app.listen(process.env.PORT || 3000, () => console.log('API no ar'));
}