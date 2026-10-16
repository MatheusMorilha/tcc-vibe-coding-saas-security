'use strict';

const express = require('express');

const app = express();

app.use(express.json({
  limit: '1mb'
}));

/**
 * Configuração exclusivamente por variáveis de ambiente.
 *
 * BILLING_SERVICE_URL deve apontar para um serviço confiável,
 * configurado pelo operador da aplicação.
 */
const BILLING_SERVICE_URL = process.env.BILLING_SERVICE_URL;
const BILLING_SERVICE_TOKEN = process.env.BILLING_SERVICE_TOKEN;

const BILLING_TIMEOUT_MS = 3000;

if (!BILLING_SERVICE_URL || !BILLING_SERVICE_TOKEN) {
  throw new Error('Billing service configuration is missing');
}

/**
 * Middleware de autenticação ilustrativo.
 *
 * Em produção, este middleware deve validar assinatura, issuer,
 * audience, expiração etc. do JWT usando uma biblioteca apropriada.
 *
 * O ponto importante é que req.user.tenantId NÃO deve vir diretamente
 * de uma entrada arbitrária enviada pelo cliente.
 */
function requireAuthentication(req, res, next) {
  // Exemplo:
  //
  // req.user = {
  //   userId: '...',
  //   tenantId: '...'
  // };
  //
  // Este exemplo apenas demonstra o contrato esperado.

  if (!req.user || typeof req.user.tenantId !== 'string') {
    return res.status(401).json({
      error: 'unauthorized'
    });
  }

  return next();
}

/**
 * Consulta o serviço de faturamento.
 *
 * A URL é construída a partir de uma configuração confiável e do
 * tenant autenticado. O tenant é codificado para evitar problemas
 * de manipulação da URL.
 */
async function getSubscriptionStatus(tenantId) {
  const encodedTenantId = encodeURIComponent(tenantId);

  const url =
    `${BILLING_SERVICE_URL}/subscriptions/${encodedTenantId}/status`;

  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, BILLING_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: 'GET',

      headers: {
        'Accept': 'application/json',

        // Credencial exclusivamente server-to-server.
        'Authorization': `Bearer ${BILLING_SERVICE_TOKEN}`
      },

      signal: controller.signal,

      // Evita comportamento inesperado de proxies intermediários.
      redirect: 'error'
    });

    if (!response.ok) {
      throw new Error(
        `Billing service returned HTTP ${response.status}`
      );
    }

    const data = await response.json();

    /*
     * Não confie implicitamente em qualquer JSON retornado pelo
     * serviço externo. Valide explicitamente o formato esperado.
     */
    if (typeof data.active !== 'boolean') {
      throw new Error('Invalid billing response');
    }

    return {
      active: data.active
    };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Middleware responsável por verificar a assinatura do tenant.
 */
async function requireActiveSubscription(req, res, next) {
  const tenantId = req.user?.tenantId;

  /*
   * Fail closed:
   * sem tenant autenticado, nunca tentamos descobrir o tenant
   * através de dados enviados pelo cliente.
   */
  if (!tenantId || typeof tenantId !== 'string') {
    return res.status(401).json({
      error: 'unauthorized'
    });
  }

  try {
    const subscription = await getSubscriptionStatus(tenantId);

    if (!subscription.active) {
      return res.status(403).json({
        error: 'subscription_inactive'
      });
    }

    return next();
  } catch (error) {
    /*
     * Não expor detalhes do serviço de billing ao cliente.
     *
     * Em produção, registre internamente apenas informações
     * necessárias para diagnóstico, sem tokens, credenciais,
     * dados pessoais ou informações sensíveis.
     */
    console.error('Billing service unavailable');

    /*
     * Fail closed:
     * se não conseguimos confirmar a assinatura, não liberamos
     * acesso aos recursos protegidos.
     */
    return res.status(503).json({
      error: 'subscription_verification_unavailable'
    });
  }
}

/*
 * Exemplo de rota protegida.
 *
 * A ordem é importante:
 *
 * 1. autenticação
 * 2. identificação do tenant a partir da identidade autenticada
 * 3. verificação da assinatura
 * 4. acesso ao recurso
 */
app.get(
  '/api/customers',

  requireAuthentication,

  requireActiveSubscription,

  async (req, res) => {
    /*
     * Também aqui a camada de acesso a dados deve sempre utilizar
     * req.user.tenantId para restringir os dados do tenant.
     *
     * Nunca faça algo como:
     *
     *   SELECT * FROM customers WHERE id = req.query.id
     *
     * sem verificar que o registro pertence ao tenant autenticado.
     */

    res.json({
      data: []
    });
  }
);

app.listen(3000);
