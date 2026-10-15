'use strict';

const crypto = require('node:crypto');
const express = require('express');
const { Pool } = require('pg');
const Redis = require('ioredis');

// ---------------------------------------------------------------------------
// Dependências (conexões compartilhadas pela aplicação)
// ---------------------------------------------------------------------------
const db = new Pool({ connectionString: process.env.DATABASE_URL, max: 10 });
const cache = new Redis(process.env.REDIS_URL, {
  maxRetriesPerRequest: 1,
  enableOfflineQueue: false, // falha rápido se o Redis estiver fora
  lazyConnect: false,
});
cache.on('error', () => {}); // evita crash por evento 'error' não tratado

const CHECK_TIMEOUT_MS = Number(process.env.HEALTH_CHECK_TIMEOUT_MS || 2000);
const HEALTH_TOKEN = process.env.HEALTH_TOKEN || '';

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

// Executa uma verificação, mede a latência e NUNCA devolve detalhes do erro
// ao cliente (mensagens podem conter host, usuário, esquema etc.).
async function runCheck(name, fn) {
  const start = process.hrtime.bigint();
  try {
    await withTimeout(fn(), CHECK_TIMEOUT_MS);
    return { name, status: 'up', latencyMs: elapsedMs(start) };
  } catch (err) {
    console.error(`[health] falha em "${name}":`, err.message); // detalhe só no log
    const reason = err.message === 'timeout' ? 'timeout' : 'unavailable';
    return { name, status: 'down', latencyMs: elapsedMs(start), reason };
  }
}

function elapsedMs(start) {
  return Math.round(Number(process.hrtime.bigint() - start) / 1e6);
}

// Comparação em tempo constante (hash garante tamanhos iguais).
function tokenIsValid(provided) {
  if (!HEALTH_TOKEN || typeof provided !== 'string') return false;
  const a = crypto.createHash('sha256').update(provided).digest();
  const b = crypto.createHash('sha256').update(HEALTH_TOKEN).digest();
  return crypto.timingSafeEqual(a, b);
}

// Acesso restrito à equipe de operações.
function requireOpsToken(req, res, next) {
  if (!tokenIsValid(req.get('x-health-token'))) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// ---------------------------------------------------------------------------
// Verificações. Usam apenas comandos neutros: nenhuma consulta a tabelas de
// negócio, portanto não dependem de tenant e não expõem dados de clientes.
// ---------------------------------------------------------------------------
const checks = {
  database: { critical: true, run: () => db.query('SELECT 1') },
  cache: { critical: false, run: async () => {
      if ((await cache.ping()) !== 'PONG') throw new Error('resposta inesperada');
    } },
};

// ---------------------------------------------------------------------------
// Rotas
// ---------------------------------------------------------------------------
const router = express.Router();

router.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// Liveness: o processo está vivo? Não toca em dependências.
// Pública e mínima, adequada para probes do orquestrador.
router.get('/health/live', (req, res) => {
  res.status(200).json({ status: 'up' });
});

// Readiness/diagnóstico detalhado: restrito à equipe de operações.
router.get('/health', requireOpsToken, async (req, res) => {
  const results = await Promise.all(
    Object.entries(checks).map(([name, c]) => runCheck(name, c.run))
  );

  const criticalDown = results.some((r) => r.status === 'down' && checks[r.name].critical);
  const anyDown = results.some((r) => r.status === 'down');

  const status = criticalDown ? 'unhealthy' : anyDown ? 'degraded' : 'healthy';

  res.status(criticalDown ? 503 : 200).json({
    status,
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.round(process.uptime()),
    version: process.env.APP_VERSION || 'unknown',
    services: Object.fromEntries(
      results.map(({ name, ...rest }) => [name, rest])
    ),
  });
});

module.exports = router;

// ---------------------------------------------------------------------------
// Exemplo de uso em app.js
//
//   const rateLimit = require('express-rate-limit');
//   const app = express();
//
//   // Montar ANTES dos middlewares de autenticação e de resolução de tenant.
//   app.use(rateLimit({ windowMs: 60_000, limit: 60 }), require('./health'));
//
//   app.use(authMiddleware);
//   app.use(tenantMiddleware);
//   ...
// ---------------------------------------------------------------------------