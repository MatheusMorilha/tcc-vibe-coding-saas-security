import Fastify from 'fastify';
import pg from 'pg';
import Redis from 'ioredis';

const fastify = Fastify({ logger: true });

// Clientes de conexão (Banco de Dados e Cache)
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const redis = new Redis(process.env.REDIS_URL, { lazyConnect: true });

/**
 * Verificação do Banco de Dados PostgreSQL
 */
async function checkDatabase(){
  const start = Date.now();
  try {
    // Executa uma query simples e leve para validar a conectividade
    await pool.query('SELECT 1');
    return {
      status: 'up',
      latencyMs: Date.now() - start,
    };
  } catch (error) {
    return {
      status: 'down',
      message: error.message,
    };
  }
}

/**
 * Verificação do Cache Redis
 */
async function checkRedis(){
  const start = Date.now();
  try {
    // Ping simples ao Redis
    const response = await redis.ping();
    if (response !== 'PONG') throw new Error('Resposta inválida do Redis');

    return {
      status: 'up',
      latencyMs: Date.now() - start,
    };
  } catch (error) {
    return {
      status: 'down',
      message: error.message,
    };
  }
}

/**
 * Rota Principal de Readiness Probe (Prontidão do Serviço)
 * Usada pelo Kubernetes/Orquestrador para saber se o serviço pode receber tráfego.
 */
fastify.get('/health', async (request, reply) => {
  const [dbStatus, redisStatus] = await Promise.all([
    checkDatabase(),
    checkRedis(),
  ]);

  // Se algum serviço crítico estiver indisponível, a aplicação não está pronta
  const isHealthy = dbStatus.status === 'up' && redisStatus.status === 'up';

  const memoryUsage = process.memoryUsage();

  const responsePayload = {
    status: isHealthy ? 'healthy' : 'unhealthy',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    environment: process.env.NODE_ENV || 'development',
    services: {
      database: dbStatus,
      redis: redisStatus,
    },
    system: {
      memory: {
        rssBytes: memoryUsage.rss,
        heapUsedBytes: memoryUsage.heapUsed,
        heapTotalBytes: memoryUsage.heapTotal,
      },
    },
  };

  // Código HTTP 200 se saudável, 530/503 se houver falha de dependência
  const statusCode = isHealthy ? 200 : 503;

  return reply.code(statusCode).send(responsePayload);
});

/**
 * Rota Secundária de Liveness Probe (Vida da Aplicação)
 * Apenas confirma se o processo Node.js está rodando e não travado.
 */
fastify.get('/health/liveness', async (request, reply) => {
  return reply.code(200).send({ status: 'alive' });
});

// Inicialização do Servidor
const start = async () => {
  try {
    await redis.connect();
    await fastify.listen({ port: process.env.PORT || 3000, host: '0.0.0.0' });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();