const express = require('express');
const router = express.Router();

// Middleware simulado de autenticação e contexto do tenant
// Na aplicação real, este middleware valida o JWT e extrai req.user e req.tenantId
const authenticateTenant = (req, res, next) => {
  // Simulação: extraído do token JWT validado
  req.tenantId = req.headers['x-tenant-id'] || 'tenant_123';
  next();
};

/**
 * POST /api/v1/subscriptions/redeem-coupon
 * Resgata e aplica um cupom de desconto à assinatura do locatário.
 */
router.post('/subscriptions/redeem-coupon', authenticateTenant, async (req, res) => {
  const { couponCode } = req.body;
  const tenantId = req.tenantId;

  // 1. Validação básica de entrada
  if (!couponCode || typeof couponCode !== 'string') {
    return res.status(400).json({
      error: 'BAD_REQUEST',
      message: 'O código do cupom é obrigatório e deve ser uma string válida.'
    });
  }

  try {
    // 2. Busca a assinatura ativa do tenant (garantindo isolamento por tenantId)
    const subscription = await db.subscription.findFirst({
      where: {
        tenantId: tenantId,
        status: 'ACTIVE'
      }
    });

    if (!subscription) {
      return res.status(404).json({
        error: 'SUBSCRIPTION_NOT_FOUND',
        message: 'Nenhuma assinatura ativa foi encontrada para este locatário.'
      });
    }

    // 3. Busca e valida o cupom promocional
    const coupon = await db.coupon.findUnique({
      where: { code: couponCode.toUpperCase().trim() }
    });

    if (!coupon || !coupon.isActive) {
      return res.status(404).json({
        error: 'COUPON_INVALID',
        message: 'Cupom promocional inválido ou inativo.'
      });
    }

    // Validações de regras de negócio do cupom
    const now = new Date();
    if (coupon.expiresAt && coupon.expiresAt < now) {
      return res.status(400).json({
        error: 'COUPON_EXPIRED',
        message: 'Este cupom promocional já expirou.'
      });
    }

    if (coupon.maxRedemptions && coupon.timesRedeemed >= coupon.maxRedemptions) {
      return res.status(400).json({
        error: 'COUPON_LIMIT_REACHED',
        message: 'Este cupom atingiu o limite máximo de resgates.'
      });
    }

    // Verifica se o tenant já utilizou este cupom anteriormente
    const existingRedemption = await db.couponRedemption.findFirst({
      where: {
        tenantId: tenantId,
        couponId: coupon.id
      }
    });

    if (existingRedemption) {
      return res.status(409).json({
        error: 'COUPON_ALREADY_USED',
        message: 'Sua empresa já resgatou este cupom anteriormente.'
      });
    }

    // 4. Cálculo do novo valor da mensalidade
    const basePrice = Number(subscription.basePrice);
    let discountAmount = 0;

    if (coupon.discountType === 'PERCENTAGE') {
      discountAmount = (basePrice * Number(coupon.discountValue)) / 100;
    } else if (coupon.discountType === 'FIXED_AMOUNT') {
      discountAmount = Number(coupon.discountValue);
    }

    // Garante que o valor final não seja negativo
    const updatedMonthlyFee = Math.max(0, basePrice - discountAmount);

    // 5. Transação no banco de dados para aplicar as alterações com consistência
    const result = await db.$transaction(async (tx) => {
      // Registra o uso do cupom pelo tenant
      await tx.couponRedemption.create({
        data: {
          tenantId: tenantId,
          couponId: coupon.id,
          redeemedAt: now
        }
      });

      // Incrementa o contador de usos do cupom
      await tx.coupon.update({
        where: { id: coupon.id },
        data: { timesRedeemed: { increment: 1 } }
      });

      // Atualiza a assinatura com o cupom aplicado e o novo valor
      const updatedSubscription = await tx.subscription.update({
        where: { id: subscription.id },
        data: {
          appliedCouponId: coupon.id,
          currentMonthlyFee: updatedMonthlyFee,
          updatedAt: now
        }
      });

      return updatedSubscription;
    });

    // 6. Retorno de sucesso com o resumo financeiro atualizado
    return res.status(200).json({
      message: 'Cupom aplicado com sucesso!',
      data: {
        subscriptionId: result.id,
        originalMonthlyFee: basePrice,
        discountApplied: discountAmount,
        updatedMonthlyFee: result.currentMonthlyFee,
        coupon: {
          code: coupon.code,
          discountType: coupon.discountType,
          discountValue: coupon.discountValue
        }
      }
    });

  } catch (error) {
    console.error(`Error redeeming coupon for tenant ${tenantId}:`, error);
    return res.status(500).json({
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Ocorreu um erro ao processar o resgate do cupom.'
    });
  }
});

module.exports = router;