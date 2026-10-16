'use strict';

const express = require('express');

const app = express();

const BILLING_URL = process.env.BILLING_URL;
const BILLING_API_KEY = process.env.BILLING_API_KEY;

if (!BILLING_URL || !BILLING_API_KEY) {
  throw new Error('Billing configuration is missing');
}

/**
 * Exemplo de middleware de autenticação.
 *
 * Em produção, substitua por validação real de sessão/JWT/OIDC.
 * O ponto importante é que req.user.tenantId seja derivado
 * de uma identidade autenticada e confiável.
 */
function requireAuthentication(req, res, next) {
  // Exemplo:
  // req.user = { id: 'user-123', tenantId: 'tenant-456' };

  if (!req.user || !req.user.tenantId) {
    return res.status(401).json({
      error: 'unauthorized'
    });
  }

  next();
}

/**
 * Consulta o serviço de faturamento.
 *
 * Fail closed:
 * - assinatura explicitamente inativa -> bloqueia
 * - tenant inexistente -> bloqueia
 * - erro/timeout do billing -> bloqueia
 */
async function checkSubscription(tenantId) {
  const controller = new AbortController();

  // Evita que uma dependência externa mantenha a requisição
  // aberta indefinidamente.
  const timeout = setTimeout(() => controller.abort(), 3000);

  try {
    const response = await fetch(
      `${BILLING_URL}/v1/tenants/${encodeURIComponent(tenantId)}/subscription`,
      {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${BILLING_API_KEY}`
        },
        signal: controller.signal
      }
    );

    if (!response.ok) {
      // Não confia em mensagens retornadas pelo serviço externo.
      throw new Error(`Billing service returned HTTP ${response.status}`);
    }

    const data = await response.json();

    // Validação mínima da resposta externa.
    if (typeof data.active !== 'boolean') {
      throw new Error('Invalid billing response');
    }

    return data.active;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Middleware responsável pelo controle de assinatura.
 */
async function requireActiveSubscription(req, res, next) {
  // O tenant vem da identidade autenticada, nunca diretamente
  // de req.query, req.body ou req.params.
  const tenantId = req.user.tenantId;

  try {
    const active = await checkSubscription(tenantId);

    if (!active) {
      return res.status(402).json({
        error: 'subscription_inactive'
      });
    }

    // Mantém o contexto do tenant disponível para as camadas seguintes.
    req.tenant = {
      id: tenantId
    };

    return next();
  } catch (error) {
    // Logue detalhes internamente, sem expor informações
    // do serviço de billing ao cliente.
    console.error('Subscription verification failed', {
      tenantId,
      error: error.message
    });

    // Fail closed: se não conseguimos verificar a assinatura,
    // não liberamos o acesso.
    return res.status(503).json({
      error: 'subscription_verification_unavailable'
    });
  }
}

/*
 * Ordem importante:
 *
 * 1. autenticar o usuário
 * 2. determinar o tenant pela identidade autenticada
 * 3. verificar a assinatura
 * 4. acessar os dados do tenant
 */
app.use('/api',
  requireAuthentication,
  requireActiveSubscription
);

app.get('/api/customers', async (req, res) => {
  // O acesso ao banco também deve utilizar req.tenant.id
  // como parte obrigatória do filtro.
  //
  // Exemplo:
  //
  // SELECT ...
  // FROM customers
  // WHERE tenant_id = req.tenant.id

  res.json({
    tenantId: req.tenant.id,
    customers: []
  });
});

app.listen(3000);
