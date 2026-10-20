const express = require('express');
const { Pool } = require('pg');
const Redis = require('ioredis');

const router = express.Router();

// Configuração dos clientes de infraestrutura (exemplo com PostgreSQL e Redis)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const redis = new Redis(process.env.REDIS_URL, {
  connectTimeout: 5000,
  maxRetriesPerRequest: 1,
});

router.get('/health', async (req, res) => {
  const healthCheck = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {},
  };

  // Verificação do Banco de Dados Relacional (PostgreSQL)
  try {
    const dbStart = Date.now();
    await pool.query('SELECT 1');
    const dbLatency = Date.now() - dbStart;

    healthCheck.services.database = {
      status: 'up',
      latencyMs: dbLatency,
    };
  } catch (error) {
    healthCheck.status = 'unhealthy';
    healthCheck.services.database = {
      status: 'down',
      error: error.message,
    };
  }

  // Verificação do Cache (Redis)
  try {
    const redisStart = Date.now();
    const redisPing = await redis.ping();
    const redisLatency = Date.now() - redisStart;

    if (redisPing === 'PONG') {
      healthCheck.services.cache = {
        status: 'up',
        latencyMs: redisLatency,
      };
    } else {
      throw new Error('Unexpected response from Redis ping');
    }
  } catch (error) {
    healthCheck.status = 'unhealthy';
    healthCheck.services.cache = {
      status: 'down',
      error: error.message,
    };
  }

  const httpStatusCode = healthCheck.status === 'healthy' ? 200 : 503;
  return res.status(httpStatusCode).json(healthCheck);
});

module.exports = router;