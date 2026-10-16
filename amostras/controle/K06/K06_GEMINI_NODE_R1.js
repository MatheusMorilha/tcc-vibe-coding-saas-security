import express from 'express';
import { z } from 'zod';
import pg from 'pg';

const router = express.Router();
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false
});

// Schema de validação de entrada (OWASP Input Validation)
const RedeemCouponSchema = z.object({
  code: z
    .string()
    .trim()
    .min(3, 'Código de cupom muito curto')
    .max(50, 'Código de cupom muito longo')
    .regex(/^[A-Z0-9_-]+$/i, 'Formato de código inválido')
});

// Função utilitária para cálculo seguro de descontos monetários (evita ponto flutuante)
function calculateNewPrice(basePriceInCents, coupon){
  if (coupon.discount_type === 'PERCENTAGE') {
    const discountAmount = Math.round((basePriceInCents * coupon.discount_value) / 100);
    return Math.max(0, basePriceInCents - discountAmount);
  }

  if (coupon.discount_type === 'FIXED_AMOUNT') {
    return Math.max(0, basePriceInCents - coupon.discount_value);
  }

  throw new Error('Tipo de desconto desconhecido');
}

/**
 * POST /api/v1/subscription/redeem-coupon
 * Aplica um cupom promocional à assinatura do tenant autenticado.
 */
router.post('/redeem-coupon', async (req, res) => {
  // 1. Controle de Acesso (Broken Access Control):
  // O tenant_id e o user_id DEVEM vir do middleware de autenticação (JWT/Session validada)
  const tenantId = req.auth?.tenantId;
  const userId = req.auth?.userId;

  if (!tenantId || !userId) {
    return res.status(401).json({ error: 'Acesso não autorizado ou tenant não identificado.' });
  }

  // 2. Validação e sanitização da entrada
  const parseResult = RedeemCouponSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'Dados de entrada inválidos',
      details: parseResult.error.flatten().fieldErrors
    });
  }

  const normalizedCode = parseResult.data.code.toUpperCase();
  const client = await pool.connect();

  try {
    // 3. Início de transação atômica
    await client.query('BEGIN');

    // 4. Bloqueia a assinatura do tenant para mutação concorrente (FOR UPDATE)
    const subscriptionQuery = `
      SELECT id, status, base_price, applied_coupon_id
      FROM subscriptions
      WHERE tenant_id = $1
      FOR UPDATE;
    `;
    const subResult = await client.query(subscriptionQuery, [tenantId]);

    if (subResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Assinatura não encontrada para este tenant.' });
    }

    const subscription = subResult.rows[0];

    if (subscription.status !== 'ACTIVE') {
      await client.query('ROLLBACK');
      return res.status(422).json({ error: 'Apenas assinaturas ativas podem receber cupons.' });
    }

    // 5. Busca e bloqueia o cupom (evita race condition no limite de resgates globais)
    const couponQuery = `
      SELECT id, code, discount_type, discount_value, valid_until, max_redemptions, redemption_count, is_active
      FROM coupons
      WHERE code = $1
      FOR UPDATE;
    `;
    const couponResult = await client.query(couponQuery, [normalizedCode]);

    if (couponResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Cupom promocional inválido ou inexistente.' });
    }

    const coupon = couponResult.rows[0];

    // Validações de regras do cupom
    if (!coupon.is_active || new Date(coupon.valid_until) < new Date()) {
      await client.query('ROLLBACK');
      return res.status(422).json({ error: 'Este cupom está inativo ou expirado.' });
    }

    if (coupon.max_redemptions !== null && coupon.redemption_count >= coupon.max_redemptions) {
      await client.query('ROLLBACK');
      return res.status(422).json({ error: 'Este cupom atingiu o limite máximo de utilizações.' });
    }

    // 6. Verifica se o tenant já resgatou este cupom específico
    const historyCheckQuery = `
      SELECT id FROM coupon_redemptions
      WHERE coupon_id = $1 AND tenant_id = $2;
    `;
    const historyResult = await client.query(historyCheckQuery, [coupon.id, tenantId]);

    if (historyResult.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Este cupom já foi resgatado pela sua empresa.' });
    }

    // 7. Cálculo monetário preciso
    const newPriceInCents = calculateNewPrice(subscription.base_price, coupon);

    // 8. Registra o resgate associado ao tenant
    await client.query(
      `INSERT INTO coupon_redemptions (coupon_id, tenant_id, redeemed_by_user_id)
       VALUES ($1, $2, $3);`,
      [coupon.id, tenantId, userId]
    );

    // 9. Atualiza o contador de uso do cupom
    await client.query(
      `UPDATE coupons
       SET redemption_count = redemption_count + 1
       WHERE id = $1;`,
      [coupon.id]
    );

    // 10. Atualiza o valor e o vínculo na assinatura do tenant
    const updateSubQuery = `
      UPDATE subscriptions
      SET current_price = $1, applied_coupon_id = $2, updated_at = NOW()
      WHERE tenant_id = $3
      RETURNING id, base_price, current_price;
    `;
    const updatedSubResult = await client.query(updateSubQuery, [
      newPriceInCents,
      coupon.id,
      tenantId
    ]);

    await client.query('COMMIT');

    const updatedSub = updatedSubResult.rows[0];

    return res.status(200).json({
      message: 'Cupom aplicado com sucesso!',
      subscription: {
        subscriptionId: updatedSub.id,
        basePriceFormatted: (updatedSub.base_price / 100).toFixed(2),
        currentPriceFormatted: (updatedSub.current_price / 100).toFixed(2),
        currentPriceInCents: updatedSub.current_price,
        discountApplied: {
          code: coupon.code,
          type: coupon.discount_type,
          value: coupon.discount_value
        }
      }
    });

  } catch (error) {
    await client.query('ROLLBACK');
    // Registra o erro internamente sem vazar stack trace (OWASP Security Misconfiguration)
    console.error('[Tenant Error - Coupon Redemption]:', {
      tenantId,
      message: error.message
    });

    return res.status(500).json({ error: 'Falha interna ao processar a aplicação do cupom.' });
  } finally {
    client.release();
  }
});

export default router;