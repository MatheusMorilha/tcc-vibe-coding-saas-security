import express from 'express';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';

const router = express.Router();
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL, {
  enableOfflineQueue: false, // Evita enfileirar comandos se o Redis estiver fora
  connectTimeout: 2000,
});

/**
 * Timeout utilitário para evitar que conexões travadas
 * prendam a resposta do Health Check.
 */
const withTimeout = (promise, ms = 3000) => {
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error(`Timeout de ${ms}ms excedido`)), ms)
  );
  return Promise.race([promise, timeout]);
};

/**
 * GET /health/liveness
 * Endpoint leve para o orquestrador (ex: Kubernetes) saber se o processo Node.js está vivo.
 */
router.get('/health/liveness', (req, res) => {
  return res.status(200).json({
    status: 'up',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /health/readiness
 * Endpoint completo para a equipe de operações e balanceadores de carga.
 * Verifica a conectividade real com Banco de Dados e Cache.
 */
router.get('/health/readiness', async (req, res) => {
  const startTime = Date.now();

  const checks = {
    database: { status: 'down', latencyMs: null },
    redis: { status: 'down', latencyMs: null },
  };

  let isHealthy = true;

  // 1. Verificação do Banco de Dados (Prisma / PostgreSQL)
  try {
    const dbStart = Date.now();
    await withTimeout(prisma.$queryRaw`SELECT 1`, 3000);
    checks.database.status = 'up';
    checks.database.latencyMs = Date.now() - dbStart;
  } catch (error) {
    isHealthy = false;
    checks.database.error = error.message;
  }

  // 2. Verificação do Cache (Redis)
  try {
    const redisStart = Date.now();
    const pingResult = await withTimeout(redis.ping(), 2000);
    if (pingResult === 'PONG') {
      checks.redis.status = 'up';
      checks.redis.latencyMs = Date.now() - redisStart;
    } else {
      throw new Error('Resposta inesperada do Redis');
    }
  } catch (error) {
    isHealthy = false;
    checks.redis.error = error.message;
  }

  // Métricas de processo e memória
  const memoryUsage = process.memoryUsage();
  const systemInfo = {
    uptime: process.uptime(),
    memory: {
      rssMB: Math.round(memoryUsage.rss / 1024 / 1024),
      heapUsedMB: Math.round(memoryUsage.heapUsed / 1024 / 1024),
    },
  };

  const responsePayload = {
    status: isHealthy ? 'healthy' : 'unhealthy',
    timestamp: new Date().toISOString(),
    totalLatencyMs: Date.now() - startTime,
    services: checks,
    system: systemInfo,
  };

  // Se algum serviço crítico falhar, retorna HTTP 503 (Service Unavailable)
  const statusCode = isHealthy ? 200 : 503;
  return res.status(statusCode).json(responsePayload);
});

export default router;