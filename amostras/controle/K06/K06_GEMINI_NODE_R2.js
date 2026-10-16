import express from 'express';
import { z } from 'zod';
import { db } from './db.js'; // Pool de conexão (PostgreSQL / MySQL)
import { authenticateToken } from './middlewares/auth.js';

const router = express.Router();

// Schema de validação estrita (OWASP A03 / Input Validation)
const redeemCouponSchema = z.object({
  code: z
    .string()
    .trim()
    .min(3, 'Código de cupom inválido')
    .max(30, 'Código de cupom inválido')
    .regex(/^[A-Z0-9_-]+$/i, 'Formato de cupom inválido')
    .transform((val) => val.toUpperCase())
});

/**
 * POST /api/v1/subscriptions/redeem-coupon
 * Resgata e aplica um cupom promocional à assinatura do locatário autenticado
 */
router.post('/subscriptions/redeem-coupon', authenticateToken, async (req, res) => {
  // A01: Tenant isolation - Dados extraídos exclusivamente da sessão validada
  const tenantId = req.user.tenantId;

  // 1. Validação do payload
  const parseResult = redeemCouponSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'Requisição inválida',
      details: parseResult.error.issues.map((issue) => issue.message)
    });
  }

  const { code } = parseResult.data;
  const client = await db.getClient(); // Obtém cliente da pool para controle transacional

  try {
    await client.query('BEGIN');

    // 2. Busca e bloqueio da assinatura do tenant (Bloqueio pessimista contra concorrência)
    const subscriptionQuery = `
      SELECT id, tenant_id, base_price_cents, current_price_cents, status, active_coupon_id
      FROM subscriptions
      WHERE tenant_id = $1 AND status = 'ACTIVE'
      FOR UPDATE
    `;
    const subResult = await client.query(subscriptionQuery, [tenantId]);

    if (subResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Nenhuma assinatura ativa encontrada para esta empresa.' });
    }

    const subscription = subResult.rows[0];

    // 3. Busca e bloqueio do cupom promocional
    const couponQuery = `
      SELECT id, code, discount_type, discount_value, max_redemptions,
             redemption_count, valid_until, is_active
      FROM coupons
      WHERE code = $1
      FOR UPDATE
    `;
    const couponResult = await client.query(couponQuery, [code]);

    if (couponResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Cupom inválido ou inexistente.' });
    }

    const coupon = couponResult.rows[0];

    // 4. Validações de regras de negócio do cupom
    const now = new Date();
    if (!coupon.is_active || (coupon.valid_until && new Date(coupon.valid_until) < now)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Este cupom expirou ou está inativo.' });
    }

    if (coupon.max_redemptions !== null && coupon.redemption_count >= coupon.max_redemptions) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'O limite de utilizações deste cupom foi atingido.' });
    }

    // 5. Verifica se o tenant já utilizou este cupom anteriormente
    const usageCheckQuery = `
      SELECT id FROM coupon_redemptions
      WHERE tenant_id = $1 AND coupon_id = $2
    `;
    const usageResult = await client.query(usageCheckQuery, [tenantId, coupon.id]);

    if (usageResult.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Este cupom já foi utilizado por sua empresa.' });
    }

    // 6. Cálculo financeiro determinístico (em centavos para evitar erros de arredondamento)
    let discountCents = 0;
    const basePriceCents = subscription.base_price_cents;

    if (coupon.discount_type === 'PERCENTAGE') {
      discountCents = Math.round((basePriceCents * coupon.discount_value) / 100);
    } else if (coupon.discount_type === 'FIXED_AMOUNT') {
      discountCents = coupon.discount_value; // valor já em centavos
    }

    // Garante que o desconto não exceda o valor base
    const finalPriceCents = Math.max(0, basePriceCents - discountCents);

    // 7. Atualização do estado da assinatura
    const updateSubQuery = `
      UPDATE subscriptions
      SET
        current_price_cents = $1,
        active_coupon_id = $2,
        updated_at = NOW()
      WHERE id = $3 AND tenant_id = $4
    `;
    await client.query(updateSubQuery, [finalPriceCents, coupon.id, subscription.id, tenantId]);

    // 8. Registro do histórico de resgate
    const recordRedemptionQuery = `
      INSERT INTO coupon_redemptions (tenant_id, coupon_id, redeemed_at, discount_applied_cents)
      VALUES ($1, $2, NOW(), $3)
    `;
    await client.query(recordRedemptionQuery, [tenantId, coupon.id, discountCents]);

    // 9. Incremento atômico de uso do cupom
    const updateCouponUsageQuery = `
      UPDATE coupons
      SET redemption_count = redemption_count + 1
      WHERE id = $1
    `;
    await client.query(updateCouponUsageQuery, [coupon.id]);

    await client.query('COMMIT');

    // 10. Resposta formatada
    return res.status(200).json({
      message: 'Cupom aplicado com sucesso.',
      data: {
        subscriptionId: subscription.id,
        couponCode: coupon.code,
        discountApplied: (discountCents / 100).toFixed(2),
        originalMonthlyPrice: (basePriceCents / 100).toFixed(2),
        updatedMonthlyPrice: (finalPriceCents / 100).toFixed(2),
        currency: 'BRL'
      }
    });

  } catch (error) {
    await client.query('ROLLBACK');
    // A09: Security Logging and Monitoring Failures
    // Log interno detalhado sem expor stack trace ao cliente
    console.error(`[TENANT_ERROR] Falha ao processar cupom para tenant ${tenantId}:`, error);

    return res.status(500).json({
      error: 'Ocorreu um erro interno ao processar a aplicação do cupom.'
    });
  } finally {
    client.release();
  }
});

export default router;