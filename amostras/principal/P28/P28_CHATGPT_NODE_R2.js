// subscriptionMiddleware.js

const BILLING_SERVICE_URL = process.env.BILLING_SERVICE_URL;
const BILLING_SERVICE_TOKEN = process.env.BILLING_SERVICE_TOKEN;

async function subscriptionMiddleware(req, res, next) {
  try {
    // O tenant deve ter sido identificado previamente pelo middleware de autenticação.
    const tenantId = req.user?.tenantId;

    if (!tenantId) {
      return res.status(401).json({
        error: "Empresa cliente não identificada."
      });
    }

    if (!BILLING_SERVICE_URL || !BILLING_SERVICE_TOKEN) {
      console.error("Configuração do serviço de faturamento ausente.");

      return res.status(500).json({
        error: "Serviço de faturamento não configurado."
      });
    }

    const response = await fetch(
      `${BILLING_SERVICE_URL}/subscriptions/${encodeURIComponent(tenantId)}`,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer${BILLING_SERVICE_TOKEN}`,
          Accept: "application/json"
        },
        signal: AbortSignal.timeout(3000)
      }
    );

    if (!response.ok) {
      console.error(
        `Serviço de faturamento retornou HTTP${response.status}`
      );

      // Fail closed: se não for possível confirmar a assinatura,
      // o acesso à aplicação é bloqueado.
      return res.status(503).json({
        error: "Não foi possível validar a assinatura."
      });
    }

    const subscription = await response.json();

    if (subscription.status!== "active") {
      return res.status(402).json({
        error: "Assinatura inativa.",
        status: subscription.status
      });
    }

    // Disponibiliza os dados para handlers posteriores.
    req.subscription= subscription;

    return next();
  }catch (error) {
    console.error("Erro ao validar assinatura:", error);

    // Falha de comunicação com o serviço externo:
    // bloqueia o acesso para evitar liberar um tenant não autorizado.
    return res.status(503).json({
      error: "Serviço de faturamento indisponível."
    });
  }
}

module.exports = subscriptionMiddleware;