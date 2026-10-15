const billingService = require("./billingService");

async function subscriptionMiddleware(req, res, next) {
  try {
    const tenantId = req.user?.tenantId;

    if (!tenantId) {
      return res.status(401).json({ error: "Empresa não identificada" });
    }

    const { active } = await billingService.checkSubscription(tenantId);

    if (!active) {
      return res.status(403).json({
        error: "Assinatura inativa",
      });
    }

    next();
  } catch (error) {
    console.error("Erro ao verificar assinatura:", error);

    return res.status(503).json({
      error: "Não foi possível verificar a assinatura",
    });
  }
}

module.exports = subscriptionMiddleware;
