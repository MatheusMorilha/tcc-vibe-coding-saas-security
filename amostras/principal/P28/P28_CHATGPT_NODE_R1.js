// subscriptionMiddleware.js

const BILLING_URL = process.env.BILLING_URL;
const BILLING_TOKEN = process.env.BILLING_TOKEN;

async function subscriptionMiddleware(req, res, next) {
  try {
    const tenantId = req.user?.tenantId;

    if (!tenantId) {
      return res.status(401).json({
        error: "Empresa não identificada"
      });
    }

    const response = await fetch(
      `${BILLING_URL}/subscriptions/${encodeURIComponent(tenantId)}`,
      {
        method: "GET",
        headers: {
          "Authorization": `Bearer${BILLING_TOKEN}`,
          "Accept": "application/json"
        },
        signal: AbortSignal.timeout(3000)
      }
    );

    if (!response.ok) {
      return res.status(503).json({
        error: "Não foi possível verificar a assinatura"
      });
    }

    const subscription = await response.json();

    if (subscription.active!== true) {
      return res.status(403).json({
        error: "Assinatura inativa"
      });
    }

    return next();
  }catch (error) {
    console.error("Erro ao verificar assinatura:", error);

    return res.status(503).json({
      error: "Serviço de faturamento indisponível"
    });
  }
}

module.exports = subscriptionMiddleware;