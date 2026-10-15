const express = require('express');
const router = express.Router();

// Middleware hipotético de autenticação e contexto multitenant
// Define req.user = { userId: '...', tenantId: '...' }
const { authenticateTenant } = require('../middlewares/auth');

// Instância do ORM ou Query Builder (ex: Prisma, Knex, Sequelize)
const db = require('../config/database');

router.post('/subscriptions/redeem-coupon', authenticateTenant, async (req, res) => {
  const { couponCode } = req.body;
  const { tenantId } = req.user; // Garantia de segurança Multitenant

  if (!couponCode) {
    return res.status(400).json({
      error: 'BAD_REQUEST',
      message: 'O código do cupom é obrigatório.'
    });
  }

  try {
    // Execução em transação para garantir consistência dos dados
    const result = await db.$transaction(async (tx) => {
      // 1. Busca a assinatura ativa da empresa
      const subscription = await tx.subscription.findFirst({
        where: {
          tenantId: tenantId,
          status: 'ACTIVE'
        },
        include: { plan: true }
      });

      if (!subscription) {
        throw { status: 404, code: 'SUBSCRIPTION_NOT_FOUND', message: 'Assinatura ativa não encontrada.' };
      }

      // 2. Busca e valida o cupom promocional
      const coupon = await tx.coupon.findUnique({
        where: { code: couponCode.toUpperCase() }
      });

      if (!coupon || !coupon.isActive) {
        throw { status: 404, code: 'COUPON_INVALID', message: 'Cupom inválido ou inativo.' };
      }

      // Validação de expiração
      if (coupon.expiresAt && new Date() > new Date(coupon.expiresAt)) {
        throw { status: 400, code: 'COUPON_EXPIRED', message: 'Este cupom já expirou.' };
      }

      // Validação de limite de uso global
      if (coupon.maxRedemptions && coupon.currentRedemptions >= coupon.maxRedemptions) {
        throw { status: 400, code: 'COUPON_LIMIT_REACHED', message: 'Cupom esgotado.' };
      }

      // 3. Verifica se o tenant já utilizou este cupom anteriormente
      const existingRedemption = await tx.couponRedemption.findFirst({
        where: {
          tenantId: tenantId,
          couponId: coupon.id
        }
      });

      if (existingRedemption) {
        throw { status: 400, code: 'COUPON_ALREADY_USED', message: 'Este cupom já foi utilizado por sua empresa.' };
      }

      // 4. Cálculo do valor atualizado da mensalidade
      const originalPrice = Number(subscription.plan.price);
      let discountAmount = 0;

      if (coupon.discountType === 'PERCENTAGE') {
        discountAmount = (originalPrice * Number(coupon.discountValue)) / 100;
      } else if (coupon.discountType === 'FIXED') {
        discountAmount = Number(coupon.discountValue);
      }

      // Garante que o valor final não seja negativo
      const updatedMonthlyFee = Math.max(0, originalPrice - discountAmount);

      // 5. Atualiza a assinatura com o novo valor e vincula o cupom
      const updatedSubscription = await tx.subscription.update({
        where: { id: subscription.id },
        data: {
          discountAmount: discountAmount,
          finalPrice: updatedMonthlyFee,
          appliedCouponId: coupon.id
        }
      });

      // 6. Registra o resgate e incrementa o contador do cupom
      await tx.couponRedemption.create({
        data: {
          tenantId: tenantId,
          couponId: coupon.id,
          redeemedAt: new Date()
        }
      });

      await tx.coupon.update({
        where: { id: coupon.id },
        data: { currentRedemptions: { increment: 1 } }
      });

      return {
        originalPrice,
        discountAmount,
        updatedMonthlyFee,
        appliedCoupon: coupon.code
      };
    });

    return res.status(200).json({
      success: true,
      message: 'Cupom aplicado com sucesso!',
      data: result
    });

  } catch (error) {
    if (error.status) {
      return res.status(error.status).json({
        error: error.code,
        message: error.message
      });
    }

    console.error('Erro ao resgatar cupom:', error);
    return res.status(500).json({
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Ocorreu um erro interno ao processar o cupom.'
    });
  }
});

module.exports = router;