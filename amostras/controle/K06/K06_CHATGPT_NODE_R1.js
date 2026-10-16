const express = require('express');
const crypto = require('crypto');

const router = express.Router();

/*
 * Dependências esperadas:
 *
 * db.query(sql, params) -> Promise<{ rows: Array }>
 *
 * authenticate() -> middleware que valida o access token e coloca:
 * req.user = {
 *   id: 'user-id',
 *   tenantId: 'company-id'
 * }
 *
 * requirePermission('subscription:coupon:redeem')
 *   -> middleware de autorização
 *
 * rateLimit(...)
 *   -> rate limiter configurado para a rota
 */

const {
  db,
  authenticate,
  requirePermission,
  rateLimit
} = require('./dependencies');

// Limitação adicional para dificultar brute force/enumeration de cupons.
const redeemRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
});

router.post(
  '/api/v1/subscription/coupon',
  authenticate,
  requirePermission('subscription:coupon:redeem'),
  redeemRateLimit,
  async (req, res) => {
    /*
     * Não aceitar tenantId, companyId ou userId do cliente.
     * Eles vêm exclusivamente do contexto autenticado.
     */
    const tenantId = req.user.tenantId;

    if (!tenantId) {
      return res.status(401).json({
        error: 'unauthorized'
      });
    }

    /*
     * Validação estrita da entrada.
     *
     * O código assume cupons com formato:
     * ABC123
     * PROMO2026
     *
     * O formato pode ser adaptado à regra real do negócio.
     */
    const rawCode = req.body?.code;

    if (
      typeof rawCode !== 'string' ||
      rawCode.length < 3 ||
      rawCode.length > 32
    ) {
      return res.status(400).json({
        error: 'invalid_coupon'
      });
    }

    const couponCode = rawCode.trim().toUpperCase();

    if (!/^[A-Z0-9_-]{3,32}$/.test(couponCode)) {
      return res.status(400).json({
        error: 'invalid_coupon'
      });
    }

    const client = await db.connect();

    try {
      await client.query('BEGIN');

      /*
       * IMPORTANTE:
       * O registro da assinatura é bloqueado durante a transação.
       * Isso evita condições de corrida em duas requisições simultâneas
       * tentando aplicar cupons à mesma assinatura.
       */
      const subscriptionResult = await client.query(
        `
        SELECT
          id,
          tenant_id,
          monthly_price_cents,
          status,
          currency
        FROM subscriptions
        WHERE tenant_id = $1
          AND status = 'active'
        FOR UPDATE
        `,
        [tenantId]
      );

      if (subscriptionResult.rows.length !== 1) {
        await client.query('ROLLBACK');

        return res.status(409).json({
          error: 'subscription_unavailable'
        });
      }

      const subscription = subscriptionResult.rows[0];

      /*
       * Busca o cupom sem expor informações sobre sua existência.
       *
       * O código do cupom é tratado como dado, nunca concatenado
       * diretamente no SQL.
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

      if (couponResult.rows.length !== 1) {
        await client.query('ROLLBACK');

        /*
         * Mensagem genérica para reduzir possibilidade de
         * enumeração de cupons válidos.
         */
        return res.status(400).json({
          error: 'coupon_not_available'
        });
      }

      const coupon = couponResult.rows[0];

      const now = new Date();

      const startsAt = new Date(coupon.starts_at);
      const expiresAt = coupon.expires_at
        ? new Date(coupon.expires_at)
        : null;

      const isExpired =
        expiresAt !== null && now >= expiresAt;

      const hasNotStarted =
        now < startsAt;

      const redemptionLimitReached =
        coupon.max_redemptions !== null &&
        coupon.redeemed_count >= coupon.max_redemptions;

      if (
        coupon.active !== true ||
        hasNotStarted ||
        isExpired ||
        redemptionLimitReached
      ) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error: 'coupon_not_available'
        });
      }

      /*
       * Impede que a mesma empresa utilize o mesmo cupom
       * mais de uma vez.
       */
      const previousRedemption = await client.query(
        `
        SELECT id
        FROM coupon_redemptions
        WHERE coupon_id = $1
          AND tenant_id = $2
        LIMIT 1
        `,
        [coupon.id, tenantId]
      );

      if (previousRedemption.rows.length > 0) {
        await client.query('ROLLBACK');

        return res.status(409).json({
          error: 'coupon_already_redeemed'
        });
      }

      const currentPrice = Number(subscription.monthly_price_cents);

      if (!Number.isSafeInteger(currentPrice) || currentPrice < 0) {
        throw new Error('Invalid subscription price in database');
      }

      /*
       * Calculamos valores monetários em centavos inteiros.
       * Não usamos Number para operações envolvendo valores
       * fracionários de moeda.
       */
      let discountCents;

      if (coupon.discount_type === 'percentage') {
        /*
         * discount_value = percentual em centésimos.
         *
         * Exemplo:
         * 1500 = 15,00%
         *
         * desconto = preço * 1500 / 10000
         */
        const percentage = Number(coupon.discount_value);

        if (
          !Number.isSafeInteger(percentage) ||
          percentage <= 0 ||
          percentage > 10000
        ) {
          throw new Error('Invalid coupon percentage in database');
        }

        discountCents = Math.floor(
          (currentPrice * percentage) / 10000
        );
      } else if (coupon.discount_type === 'fixed') {
        discountCents = Number(coupon.discount_value);

        if (
          !Number.isSafeInteger(discountCents) ||
          discountCents <= 0
        ) {
          throw new Error('Invalid fixed coupon value in database');
        }
      } else {
        throw new Error('Invalid coupon type in database');
      }

      /*
       * Nunca permitir que o desconto gere mensalidade negativa.
       */
      discountCents = Math.min(discountCents, currentPrice);

      const updatedPrice = currentPrice - discountCents;

      /*
       * Atualiza a assinatura somente dentro da mesma transação
       * que registrará o resgate.
       */
      await client.query(
        `
        UPDATE subscriptions
        SET
          monthly_price_cents = $1,
          updated_at = NOW()
        WHERE id = $2
          AND tenant_id = $3
        `,
        [
          updatedPrice,
          subscription.id,
          tenantId
        ]
      );

      /*
       * O INSERT deve possuir uma constraint UNIQUE em:
       *
       * UNIQUE (coupon_id, tenant_id)
       *
       * Assim, mesmo com concorrência ou falha de aplicação,
       * o banco também garante a regra de negócio.
       */
      await client.query(
        `
        INSERT INTO coupon_redemptions (
          id,
          coupon_id,
          tenant_id,
          subscription_id,
          redeemed_by_user_id,
          discount_cents,
          created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        `,
        [
          crypto.randomUUID(),
          coupon.id,
          tenantId,
          subscription.id,
          req.user.id,
          discountCents
        ]
      );

      await client.query(
        `
        UPDATE coupons
        SET redeemed_count = redeemed_count + 1
        WHERE id = $1
        `,
        [coupon.id]
      );

      /*
       * Auditoria sem registrar o código completo do cupom.
       * O ideal é que esse mecanismo seja integrado ao sistema
       * central de auditoria da aplicação.
       */
      await client.query(
        `
        INSERT INTO audit_logs (
          id,
          tenant_id,
          user_id,
          action,
          resource_type,
          resource_id,
          metadata,
          created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        `,
        [
          crypto.randomUUID(),
          tenantId,
          req.user.id,
          'subscription.coupon_redeemed',
          'subscription',
          subscription.id,
          JSON.stringify({
            couponId: coupon.id,
            discountCents,
            currency: subscription.currency
          })
        ]
      );

      await client.query('COMMIT');

      return res.status(200).json({
        subscriptionId: subscription.id,
        currency: subscription.currency,
        previousMonthlyPriceCents: currentPrice,
        discountCents,
        monthlyPriceCents: updatedPrice
      });
    } catch (error) {
      await client.query('ROLLBACK');

      /*
       * Logar detalhes internamente, sem retorná-los ao cliente.
       *
       * Não retornar error.message evita vazamento de informações
       * internas, SQL, estrutura do banco etc.
       */
      console.error('Coupon redemption failed', {
        tenantId,
        userId: req.user?.id,
        error
      });

      /*
       * Em produção, erros esperados de constraint podem ser
       * tratados especificamente pelo código SQLSTATE.
       */
      return res.status(500).json({
        error: 'internal_error'
      });
    } finally {
      client.release();
    }
  }
);

module.exports = router;
