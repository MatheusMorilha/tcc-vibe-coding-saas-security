const express = require("express");
const { Pool } = require("pg");

const router = express.Router();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: true }
    : false,
});

// Middleware de autenticação.
// Em produção, valide o JWT/sessão antes desta rota e preencha req.user.
function requireAuth(req, res, next) {
  // Exemplo:
  // req.user = {
  //   id: "...",
  //   tenantId: "...",
  //   role: "admin"
  // };

  if (!req.user || !req.user.id || !req.user.tenantId) {
    return res.status(401).json({
      error: "unauthorized",
    });
  }

  next();
}

router.post("/api/v1/billing/coupons/redeem", requireAuth, async (req, res) => {
  const { code } = req.body;

  // Validação de entrada / limite de tamanho.
  if (typeof code !== "string" || code.length < 1 || code.length > 64) {
    return res.status(400).json({
      error: "invalid_coupon",
      message: "Código de cupom inválido.",
    });
  }

  // Normalização controlada.
  const couponCode = code.trim().toUpperCase();

  if (!/^[A-Z0-9_-]+$/.test(couponCode)) {
    return res.status(400).json({
      error: "invalid_coupon",
      message: "Código de cupom inválido.",
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    /*
     * IMPORTANTE:
     * tenantId vem do usuário autenticado, e NÃO do body.
     * Isso impede que um cliente tente resgatar cupom
     * alterando tenant_id manualmente.
     */
    const tenantId = req.user.tenantId;

    /*
     * Bloqueia a assinatura durante a operação.
     * Isso evita condições de corrida quando duas requisições
     * tentam alterar a mesma assinatura simultaneamente.
     */
    const subscriptionResult = await client.query(
      `
      SELECT
        id,
        tenant_id,
        monthly_price_cents,
        currency,
        status
      FROM subscriptions
      WHERE tenant_id = $1
        AND status = 'active'
      FOR UPDATE
      `,
      [tenantId]
    );

    if (subscriptionResult.rowCount !== 1) {
      await client.query("ROLLBACK");

      return res.status(409).json({
        error: "active_subscription_required",
        message: "Não foi encontrada uma assinatura ativa.",
      });
    }

    const subscription = subscriptionResult.rows[0];

    /*
     * Busca o cupom dentro da mesma transação.
     *
     * FOR UPDATE é importante caso o cupom tenha:
     * - limite global de utilização;
     * - limite por empresa;
     * - quantidade restante.
     */
    const couponResult = await client.query(
      `
      SELECT
        id,
        code,
        discount_type,
        discount_value,
        max_redemptions,
        redeemed_count,
        starts_at,
        expires_at,
        active
      FROM coupons
      WHERE code = $1
      FOR UPDATE
      `,
      [couponCode]
    );

    /*
     * Não diferenciamos "cupom inexistente" de alguns estados
     * inválidos para não facilitar enumeração de cupons.
     */
    if (couponResult.rowCount !== 1) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "invalid_coupon",
        message: "Cupom inválido ou indisponível.",
      });
    }

    const coupon = couponResult.rows[0];
    const now = new Date();

    const startsAt = coupon.starts_at
      ? new Date(coupon.starts_at)
      : null;

    const expiresAt = coupon.expires_at
      ? new Date(coupon.expires_at)
      : null;

    if (
      !coupon.active ||
      (startsAt && now < startsAt) ||
      (expiresAt && now > expiresAt) ||
      (
        coupon.max_redemptions !== null &&
        coupon.redeemed_count >= coupon.max_redemptions
      )
    ) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "invalid_coupon",
        message: "Cupom inválido ou indisponível.",
      });
    }

    /*
     * Impede que a mesma empresa utilize o mesmo cupom duas vezes.
     */
    const previousRedemption = await client.query(
      `
      SELECT id
      FROM coupon_redemptions
      WHERE tenant_id = $1
        AND coupon_id = $2
      LIMIT 1
      `,
      [tenantId, coupon.id]
    );

    if (previousRedemption.rowCount > 0) {
      await client.query("ROLLBACK");

      return res.status(409).json({
        error: "coupon_already_redeemed",
        message: "Este cupom já foi utilizado.",
      });
    }

    /*
     * Calcula o desconto usando centavos inteiros.
     * Evita problemas de precisão típicos de Number para dinheiro.
     */
    const originalPrice = Number(subscription.monthly_price_cents);

    let discountCents;

    if (coupon.discount_type === "percentage") {
      /*
       * Exemplo: 15% = discount_value 15.
       *
       * Math.floor evita gerar uma fração de centavo.
       */
      discountCents = Math.floor(
        originalPrice * Number(coupon.discount_value) / 100
      );
    } else if (coupon.discount_type === "fixed") {
      discountCents = Number(coupon.discount_value);
    } else {
      await client.query("ROLLBACK");

      return res.status(500).json({
        error: "coupon_configuration_error",
      });
    }

    /*
     * Nunca permitimos mensalidade negativa.
     */
    discountCents = Math.max(0, Math.min(discountCents, originalPrice));

    const updatedPrice = originalPrice - discountCents;

    /*
     * Registra o resgate.
     *
     * Existe também uma constraint UNIQUE recomendada:
     * UNIQUE (tenant_id, coupon_id)
     */
    await client.query(
      `
      INSERT INTO coupon_redemptions (
        tenant_id,
        coupon_id,
        subscription_id,
        redeemed_by_user_id,
        discount_cents,
        original_price_cents,
        final_price_cents
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      `,
      [
        tenantId,
        coupon.id,
        subscription.id,
        req.user.id,
        discountCents,
        originalPrice,
        updatedPrice,
      ]
    );

    /*
     * Atualiza o contador somente dentro da transação.
     */
    await client.query(
      `
      UPDATE coupons
      SET redeemed_count = redeemed_count + 1
      WHERE id = $1
      `,
      [coupon.id]
    );

    /*
     * Atualiza a assinatura.
     *
     * Em um sistema real, pode ser preferível armazenar o cupom
     * e o desconto como componentes de preço, em vez de sobrescrever
     * permanentemente o preço-base.
     */
    await client.query(
      `
      UPDATE subscriptions
      SET monthly_price_cents = $1,
          updated_at = NOW()
      WHERE id = $2
        AND tenant_id = $3
      `,
      [updatedPrice, subscription.id, tenantId]
    );

    await client.query("COMMIT");

    return res.status(200).json({
      subscription: {
        id: subscription.id,
        currency: subscription.currency,
        originalMonthlyPriceCents: originalPrice,
        discountCents,
        monthlyPriceCents: updatedPrice,
      },
      coupon: {
        code: coupon.code,
        discountType: coupon.discount_type,
      },
    });
  } catch (error) {
    await client.query("ROLLBACK");

    /*
     * Constraint UNIQUE protege contra condições de corrida
     * caso duas requisições tentem resgatar o mesmo cupom.
     */
    if (error.code === "23505") {
      return res.status(409).json({
        error: "coupon_already_redeemed",
        message: "Este cupom já foi utilizado.",
      });
    }

    // Log interno, sem expor stack trace ou detalhes do banco ao cliente.
    console.error("Coupon redemption failed", {
      userId: req.user?.id,
      tenantId: req.user?.tenantId,
      error: error.message,
    });

    return res.status(500).json({
      error: "internal_server_error",
    });
  } finally {
    client.release();
  }
});

module.exports = router;
