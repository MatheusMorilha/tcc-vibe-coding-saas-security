import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client'; // Exemplo de ORM SQL
import Redis from 'ioredis';

const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

/**
 * Avalia a saúde do Banco de Dados executando uma query minimalista
 */
async function checkDatabase(): Promise<{ status: 'UP' | 'DOWN'; latencyMs: number; error?: string }> {
  const start = performance.now();
  try {
    // Query ultra-leve para validar conexão física e autorização
    await prisma.$queryRaw`SELECT 1`;
    const latencyMs = Math.round(performance.now() - start);
    return { status: 'UP', latencyMs };
  } catch (err: any) {
    const latencyMs = Math.round(performance.now() - start);
    return { status: 'DOWN', latencyMs, error: err.message || 'Erro de conexão com o banco' };
  }
}

/**
 * Avalia a saúde do Redis executando um PING
 */
async function checkRedis(): Promise<{ status: 'UP' | 'DOWN'; latencyMs: number; error?: string }> {
  const start = performance.now();
  try {
    const response = await redis.ping();
    const latencyMs = Math.round(performance.now() - start);
    if (response === 'PONG') {
      return { status: 'UP', latencyMs };
    }
    return { status: 'DOWN', latencyMs, error: 'Resposta inesperada do Redis' };
  } catch (err: any) {
    const latencyMs = Math.round(performance.now() - start);
    return { status: 'DOWN', latencyMs, error: err.message || 'Erro de conexão com Redis' };
  }
}

/**
 * Controller principal da rota /health
 */
export async function getHealthStatus(req: Request, res: Response){
  // Executa as verificações em paralelo para minimizar a latência da chamada
  const [dbHealth, redisHealth] = await Promise.all([
    checkDatabase(),
    checkRedis()
  ]);

  const isDbUp = dbHealth.status === 'UP';
  const isRedisUp = redisHealth.status === 'UP';

  // Lógica de determinação do status geral da aplicação
  let overallStatus: 'UP' | 'DOWN' | 'DEGRADED' = 'UP';
  let statusCode = 200;

  if (!isDbUp && !isRedisUp) {
    overallStatus = 'DOWN';
    statusCode = 503; // Service Unavailable
  } else if (!isDbUp) {
    // Para um SaaS multilocatário, sem DB a aplicação está indisponível
    overallStatus = 'DOWN';
    statusCode = 503;
  } else if (!isRedisUp) {
    // Sem Redis a aplicação pode operar de forma degradada (ex: sem cache, caindo para queries diretas)
    overallStatus = 'DEGRADED';
    statusCode = 200; // Ou 207 Multi-Status dependendo da política de infraestrutura
  }

  const responseBody = {
    status: overallStatus,
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    environment: process.env.NODE_ENV || 'development',
    services: {
      database: dbHealth,
      redis: redisHealth
    }
  };

  return res.status(statusCode).json(responseBody);
}

import { Router } from 'express';
import { getHealthStatus } from './health.controller';

const router = Router();

// Rota utilizada pelo Load Balancer (ALB / Nginx / Kubernetes Readiness Probe)
router.get('/health', getHealthStatus);

export default router;