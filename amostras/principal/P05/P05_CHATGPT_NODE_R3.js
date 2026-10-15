const express = require('express');
const { Pool } = require('pg');
const Redis = require('ioredis');

const app = express();

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const cache = new Redis(process.env.REDIS_URL);

app.get('/health', async (req, res) => {
  const services = {};

  try {
    await db.query('SELECT 1');
    services.database = 'ok';
  } catch {
    services.database = 'error';
  }

  try {
    await cache.ping();
    services.cache = 'ok';
  } catch {
    services.cache = 'error';
  }

  const healthy = Object.values(services).every(
    (status) => status === 'ok'
  );

  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'ok' : 'degraded',
    services,
    timestamp: new Date().toISOString(),
  });
});

app.listen(process.env.PORT || 3000);
