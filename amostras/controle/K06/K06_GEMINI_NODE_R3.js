import express from 'express';
import { z } from 'zod';
import pg from 'pg'; // Exemplo usando 'pg' (PostgreSQL)

const router = express.Router();
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

// Schema de validação estrito (OWASP A03 / A04 - Mass Assignment & Validation)
const redeemCouponSchema = z.object({
  code: z
    .string()
    .trim()
    .min(3, 'Código de cupom muito curto.')
    .max(50, 'Código de cupom muito longo.')
    .regex(/^[A-Za-z0-9_-]+$/, 'Formato de cupom inválido.')
});

/**
 * Middleware mock de autenticação e RBAC (OWASP A01 / A07)
 * Em produção, substitua pelo seu middleware de JWT / sessão.
 */
function authenticateAndAuthorize(requiredRole = 'ADMIN'){
  return (req, res, next) => {
    // req.user deve vir da validação prévia de token seguro (JWT verificado via chave assimétrica)
    if (!req.user || !req.user.tenantId) {
      return res.status(401).json({ error: 'Não autenticado.' });
    }

    if (req.user.role !== requiredRole) {
      return res.status(403).json({ error: 'Acesso negado: permissão insuficiente para gerenciar assinaturas.' });
    }

    next();
  };
}

/**
 * POST /api/v1/subscription/redeem-coupon
 */
router.post(
  '/api/v1/subscription/redeem-coupon',
  authenticateAndAuthorize('ADMIN'),
  async (req, res) => {
    // 1. Validação do payload
    const parseResult = redeemCouponSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        error: 'Dados de requisição inválidos.',
        details: parseResult.error.flatten().fieldErrors
      });
    }

    const { code } = parseResult.data;
    const tenantId = req.user.tenantId;

    const client = await pool.connect();

    try {
      // Inicia transação com nível de isolamento adequado
      await client.query('BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED');

      // 2. Busca e bloqueia a assinatura do tenant atual (Garante isolamento multi-tenant)
      const subQuery = `
        SELECT id, base_amount_cents, current_amount_cents, active_coupon_id, status
        FROM subscriptions
        WHERE tenant_id = $1 AND status = 'ACTIVE'
        FOR UPDATE
      `;
      const subResult = await client.query(subQuery, [tenantId]);

      if (subResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Nenhuma assinatura ativa encontrada para este locatário.' });
      }

      const subscription = subResult.rows[0];

      // 3. Busca o cupom com bloqueio para evitar Race Condition (OWASP A04)
      const couponQuery = `
        SELECT id, code, discount_type, discount_value, max_redemptions, times_redeemed, expires_at, is_active
        FROM promotional_coupons
        WHERE code = $1
        FOR UPDATE
      `;
      const couponResult = await client.query(couponQuery, [code.toUpperCase()]);

      if (couponResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Cupom promocional inválido ou inexistente.' });
      }

      const coupon = couponResult.rows[0];

      // 4. Verificações de validade e elegibilidade
      const now = new Date();
      if (!coupon.is_active || (coupon.expires_at && new Date(coupon.expires_at) < now)) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Este cupom expirou ou está inativo.' });
      }

      if (coupon.max_redemptions !== null && coupon.times_redeemed >= coupon.max_redemptions) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Limite de utilizações deste cupom foi atingido.' });
      }

      // Verifica se o locatário já resgatou este cupom específico anteriormente
      const redemptionCheckQuery = `
        SELECT 1 FROM coupon_redemptions
        WHERE tenant_id = $1 AND coupon_id = $2
        LIMIT 1
      `;
      const redemptionCheck = await client.query(redemptionCheckQuery, [tenantId, coupon.id]);

      if (redemptionCheck.rows.length > 0) {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'Este cupom já foi resgatado anteriormente por esta empresa.' });
      }

      // 5. Cálculo seguro do desconto (valores mantidos em centavos)
      const baseAmountCents = Number(subscription.base_amount_cents);
      let calculatedAmountCents = baseAmountCents;

      if (coupon.discount_type === 'PERCENTAGE') {
        const discountFraction = Number(coupon.discount_value) / 100;
        const discountCents = Math.round(baseAmountCents * discountFraction);
        calculatedAmountCents = Math.max(0, baseAmountCents - discountCents);
      } else if (coupon.discount_type === 'FIXED_AMOUNT') {
        const discountCents = Number(coupon.discount_value);
        calculatedAmountCents = Math.max(0, baseAmountCents - discountCents);
      } else {
        await client.query('ROLLBACK');
        return res.status(500).json({ error: 'Tipo de desconto não suportado pelo sistema.' });
      }

      // 6. Atualização dos registros no banco de dados
      // Atualiza assinatura da empresa
      const updateSubQuery = `
        UPDATE subscriptions
        SET current_amount_cents = $1,
            active_coupon_id = $2,
            updated_at = NOW()
        WHERE id = $3 AND tenant_id = $4
      `;
      await client.query(updateSubQuery, [
        calculatedAmountCents,
        coupon.id,
        subscription.id,
        tenantId
      ]);

      // Incrementa o contador de utilizações globais do cupom
      const updateCouponQuery = `
        UPDATE promotional_coupons
        SET times_redeemed = times_redeemed + 1
        WHERE id = $1
      `;
      await client.query(updateCouponQuery, [coupon.id]);

      // Registra a trilha de auditoria do resgate
      const insertRedemptionQuery = `
        INSERT INTO coupon_redemptions (tenant_id, coupon_id, subscription_id, redeemed_at)
        VALUES ($1, $2, $3, NOW())
      `;
      await client.query(insertRedemptionQuery, [tenantId, coupon.id, subscription.id]);

      // Confirma transação
      await client.query('COMMIT');

      // 7. Retorno com valores formatados
      return res.status(200).json({
        message: 'Cupom resgatado com sucesso!',
        subscription: {
          id: subscription.id,
          originalMonthlyAmount: (baseAmountCents / 100).toFixed(2),
          updatedMonthlyAmount: (calculatedAmountCents / 100).toFixed(2),
          currency: 'BRL',
          appliedCoupon: coupon.code
        }
      });
    } catch (error) {
      await client.query('ROLLBACK');

      // OWASP A09: Security Logging and Monitoring Failures (log interno seguro sem vazar para a resposta)
      console.error('[SUBSCRIPTION_COUPON_ERROR]', {
        tenantId,
        message: error.message,
        timestamp: new Date().toISOString()
      });

      return res.status(500).json({
        error: 'Falha interna ao processar o resgate do cupom. Tente novamente mais tarde.'
      });
    } finally {
      client.release();
    }
  }
);

export default router;