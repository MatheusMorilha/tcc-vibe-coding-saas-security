const express = require("express");
const {Pool }= require("pg");
const Redis = require("ioredis");

const app = express();

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const cache = new Redis(process.env.REDIS_URL);

app.get("/health", async (req, res)=> {
  const services = {};

  // Banco de dados
  try {
    await db.query("SELECT 1");
    services.database= { status: "ok" };
  }catch (error) {
    services.database= {
      status: "error",
      error: error.message,
    };
  }

  // Cache
  try {
    await cache.ping();
    services.cache= { status: "ok" };
  }catch (error) {
    services.cache= {
      status: "error",
      error: error.message,
    };
  }

  const healthy = Object.values(services).every(
    (service)=> service.status=== "ok"
  );

  res.status(healthy? 200 : 503).json({
    status: healthy? "ok" : "degraded",
    services,
    timestamp: new Date().toISOString(),
  });
});

app.listen(process.env.PORT || 3000);