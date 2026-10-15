const express = require('express');
const router = express.Router();

/**
 * Exemplo com um ORM/Query Builder fictício (como Prisma ou Sequelize).
 * Adapte as chamadas de banco de dados para a biblioteca utilizada no projeto.
 */
const db = require('../config/database');

/**
 * POST /api/v1/subscription/redeem-coupon
 * Resgata um cupom promocional e aplica o desconto à assinatura do tenant.
 */
router.post('/redeem-coupon', async (req, res) => {
  const { couponCode } = req.body;

  // Garante a segurança multilocatária através do contexto do usuário autenticado
  const tenantId = req.user?.companyId;

  if (!couponCode) {
    return res.status(400).json({ error: 'O código do cupom é obrigatório.' });
  }

  if (!tenantId) {
    return res.status(401).json({ error: 'Contexto de empresa (tenant) não identificado.' });
  }

  // Utilização de transação para garantir consistência dos dados
  const session = await db.startTransaction();

  try {
    // 1. Buscar a assinatura ativa da empresa cliente (isolamento por tenantId)
    const subscription = await db.Subscription.findOne({
      where: { companyId: tenantId, status: 'ACTIVE' },
      transaction: session,
    });

    if (!subscription) {
      await session.rollback();
      return res.status(404).json({ error: 'Assinatura ativa não encontrada para esta empresa.' });
    }

    // 2. Buscar e validar o cupom promocional
    const coupon = await db.Coupon.findOne({
      where: { code: couponCode.toUpperCase(), active: true },
      transaction: session,
    });

    if (!coupon) {
      await session.rollback();
      return res.status(404).json({ error: 'Cupom promocional inválido ou inativo.' });
    }

    // Validação de expiração
    if (coupon.expiresAt && new Date(coupon.expiresAt) < new Date()) {
      await session.rollback();
      return res.status(400).json({ error: 'Este cupom promocional já expirou.' });
    }

    // Validação de limite de usos globais
    if (coupon.maxRedemptions !== null && coupon.timesRedeemed >= coupon.maxRedemptions) {
      await session.rollback();
      return res.status(400).json({ error: 'Este cupom atingiu o limite máximo de resgates.' });
    }

    // 3. Verificar se o tenant já resgatou este cupom anteriormente
    const previousRedemption = await db.CouponRedemption.findOne({
      where: { companyId: tenantId, couponId: coupon.id },
      transaction: session,
    });

    if (previousRedemption) {
      await session.rollback();
      return res.status(400).json({ error: 'Sua empresa já resgatou este cupom anteriormente.' });
    }

    // 4. Calcular o valor atualizado da mensalidade
    const originalPrice = subscription.basePrice;
    let updatedPrice = originalPrice;

    if (coupon.discountType === 'PERCENTAGE') {
      const discountAmount = (originalPrice * coupon.discountValue) / 100;
      updatedPrice = Math.max(0, originalPrice - discountAmount);
    } else if (coupon.discountType === 'FIXED') {
      updatedPrice = Math.max(0, originalPrice - coupon.discountValue);
    }

    // Arredondar para 2 casas decimais para evitar problemas com ponto flutuante
    updatedPrice = Math.round(updatedPrice * 100) / 100;

    // 5. Atualizar a assinatura
    await db.Subscription.update(
      {
        appliedCouponId: coupon.id,
        currentMonthlyPrice: updatedPrice,
        updatedAt: new Date(),
      },
      { where: { id: subscription.id }, transaction: session }
    );

    // 6. Registrar o histórico de uso do cupom pela empresa
    await db.CouponRedemption.create(
      {
        companyId: tenantId,
        couponId: coupon.id,
        redeemedAt: new Date(),
        appliedDiscount: originalPrice - updatedPrice,
      },
      { transaction: session }
    );

    // 7. Incrementar o contador global de resgates do cupom
    await db.Coupon.increment('timesRedeemed', {
      by: 1,
      where: { id: coupon.id },
      transaction: session,
    });

    // Commit da transação
    await session.commit();

    // 8. Retornar resposta ao cliente
    return res.status(200).json({
      message: 'Cupom aplicado com sucesso!',
      subscription: {
        id: subscription.id,
        originalPrice,
        updatedMonthlyPrice: updatedPrice,
        discountApplied: {
          code: coupon.code,
          type: coupon.discountType,
          value: coupon.discountValue,
        },
      },
    });
  } catch (error) {
    await session.rollback();
    console.error('Erro ao resgatar cupom promocional:', error);
    return res.status(500).json({ error: 'Erro interno ao processar a aplicação do cupom.' });
  }
});

module.exports = router;