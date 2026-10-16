'use strict';

/**
 * Node.js 18+ (usa fetch nativo)
 *
 * Exemplo de uso:
 *
 * app.use(authenticateUser);
 * app.use(checkSubscription);
 *
 * app.get('/api/orders', handler);
 */

const BILLING_API_URL = process.env.BILLING_API_URL;
const BILLING_API_TOKEN = process.env.BILLING_API_TOKEN;

const BILLING_TIMEOUT_MS = 3000;

if (!BILLING_API_URL) {
  throw new Error('BILLING_API_URL não configurada');
}

if (!BILLING_API_TOKEN) {
  throw new Error('BILLING_API_TOKEN não configurado');
}

// A URL do serviço de billing vem exclusivamente da configuração
// do servidor. Nunca use uma URL fornecida pelo usuário.
const billingUrl = new URL(BILLING_API_URL);

// Opcionalmente, restrinja o host permitido para reduzir risco de SSRF.
const ALLOWED_BILLING_HOST = process.env.BILLING_API_HOST;

if (
  ALLOWED_BILLING_HOST &&
  billingUrl.hostname !== ALLOWED_BILLING_HOST
) {
  throw new Error('BILLING_API_URL aponta para um host não autorizado');
}

/**
 * Middleware que verifica se o tenant possui uma assinatura ativa.
 *
 * Pré-requisito:
 * authenticateUser deve ter validado o token/sessão e colocado
 * req.user.tenantId em uma propriedade confiável.
 */
async function checkSubscription(req, res, next) {
  try {
    /*
     * Não aceite tenantId de:
     *   req.query.tenantId
     *   req.params.tenantId
     *   req.body.tenantId
     *   headers controlados pelo cliente
     *
     * O tenant deve ser derivado da identidade autenticada.
     */
    const tenantId = req.user?.tenantId;

    if (!tenantId || typeof tenantId !== 'string') {
      return res.status(401).json({
        error: 'UNAUTHENTICATED'
      });
    }

    /*
     * Validação defensiva do identificador.
     * Adapte a expressão ao formato real dos IDs da aplicação
     * (UUID, ULID etc.).
     */
    if (
      tenantId.length > 100 ||
      !/^[a-zA-Z0-9_-]+$/.test(tenantId)
    ) {
      return res.status(403).json({
        error: 'FORBIDDEN'
      });
    }

    /*
     * AbortController impede que uma indisponibilidade do billing
     * mantenha conexões da aplicação ocupadas indefinidamente.
     */
    const controller = new AbortController();

    const timeout = setTimeout(() => {
      controller.abort();
    }, BILLING_TIMEOUT_MS);

    let billingResponse;

    try {
      /*
       * O tenantId é enviado como parâmetro da API de billing,
       * mas a origem da requisição é uma URL fixa/configurada
       * pelo servidor.
       */
      const url = new URL(billingUrl);

      url.pathname = `${url.pathname.replace(/\/$/, '')}/subscriptions`;
      url.searchParams.set('tenantId', tenantId);

      billingResponse = await fetch(url, {
        method: 'GET',

        headers: {
          'Authorization': `Bearer ${BILLING_API_TOKEN}`,
          'Accept': 'application/json'
        },

        signal: controller.signal,

        /*
         * Não siga redirects automaticamente para evitar que uma
         * resposta do serviço de billing redirecione credenciais
         * para outro host.
         */
        redirect: 'error'
      });
    } finally {
      clearTimeout(timeout);
    }

    /*
     * Falha na comunicação com o billing:
     * fail closed.
     *
     * Isso evita liberar acesso simplesmente porque o serviço externo
     * está indisponível.
     */
    if (!billingResponse.ok) {
      // Não exponha detalhes do serviço externo ao cliente.
      console.error('Billing service returned an error', {
        status: billingResponse.status,
        tenantId
      });

      return res.status(503).json({
        error: 'SUBSCRIPTION_VALIDATION_UNAVAILABLE'
      });
    }

    /*
     * Não confie cegamente no JSON recebido.
     */
    const contentType =
      billingResponse.headers.get('content-type') || '';

    if (!contentType.toLowerCase().includes('application/json')) {
      console.error('Billing service returned unexpected content type', {
        tenantId
      });

      return res.status(503).json({
        error: 'SUBSCRIPTION_VALIDATION_UNAVAILABLE'
      });
    }

    const subscription = await billingResponse.json();

    /*
     * Validação mínima do contrato externo.
     *
     * Exemplo esperado:
     * {
     *   "tenantId": "empresa-123",
     *   "active": true
     * }
     */
    if (
      !subscription ||
      typeof subscription !== 'object' ||
      typeof subscription.active !== 'boolean' ||
      subscription.tenantId !== tenantId
    ) {
      console.error('Invalid billing response', {
        tenantId
      });

      return res.status(503).json({
        error: 'SUBSCRIPTION_VALIDATION_UNAVAILABLE'
      });
    }

    /*
     * Assinatura inexistente/inativa:
     * acesso bloqueado.
     */
    if (subscription.active !== true) {
      return res.status(403).json({
        error: 'SUBSCRIPTION_INACTIVE'
      });
    }

    /*
     * Não coloque dados vindos do billing diretamente em req.user.
     * Se a aplicação precisar dessas informações, copie apenas
     * campos explicitamente permitidos pelo contrato.
     */
    req.subscription = {
      active: true
    };

    return next();
  } catch (error) {
    /*
     * Não devolva stack trace, mensagens internas, URLs ou
     * credenciais ao cliente.
     */
    if (error?.name === 'AbortError') {
      console.error('Billing request timed out', {
        tenantId: req.user?.tenantId
      });

      return res.status(503).json({
        error: 'SUBSCRIPTION_VALIDATION_UNAVAILABLE'
      });
    }

    console.error('Subscription validation failed', {
      tenantId: req.user?.tenantId,
      error: error?.message
    });

    /*
     * Fail closed.
     */
    return res.status(503).json({
      error: 'SUBSCRIPTION_VALIDATION_UNAVAILABLE'
    });
  }
}

module.exports = {
  checkSubscription
};
