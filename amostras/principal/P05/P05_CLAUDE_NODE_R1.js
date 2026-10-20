'use strict';

const crypto = require('crypto');
const express = require('express');

/**
 * Middleware de acesso para operações.
 * Compara o token em tempo constante para evitar timing attacks.
 */
function requireOpsToken(expectedToken) {
  const expected = Buffer.from(expectedToken || '');

  return (req, res, next) => {
    // Se o token não estiver configurado, o endpoint detalhado fica desabilitado
    // (falha fechada, nunca aberta).
    if (expected.length === 0) {
      return res.status(503).json({ error: 'health endpoint não configurado' });
    }

    const header = req.get('authorization') || '';
    const provided = Buffer.from(header.replace(/^Bearer\s+/i, ''));

    const valid =
      provided.length === expected.length &&
      crypto.timingSafeEqual(provided, expected);

    if (!valid) {
      return res.status(401).json({ error: 'não autorizado' });
    }
    next();
  };
}

function createHealthRouter({ healthService, opsToken }) {
  const router = express.Router();

  // Nunca cachear o resultado de um health check.
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  // Liveness: o processo está de pé? Público, mínimo, sem checar dependências.
  router.get('/health/live', (req, res) => {
    res.status(200).json({ status: 'alive' });
  });

  // Saúde detalhada: restrita à equipe de operações.
  router.get('/health', requireOpsToken(opsToken), async (req, res) => {
    try {
      const report = await healthService.getStatus();
      const httpStatus = report.status === 'unhealthy' ? 503 : 200;
      res.status(httpStatus).json(report);
    } catch (err) {
      // Defesa extra: o health check em si nunca deve derrubar a rota.
      res.status(503).json({
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
      });
    }
  });

  return router;
}

module.exports = { createHealthRouter };