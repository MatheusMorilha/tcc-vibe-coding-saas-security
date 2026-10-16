'use strict';

const http = require('node:http');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: true }
    : false,
});

/**
 * POST /api/v1/billing/coupons/redeem
 *
 * Body:
 * {
 *   "code": "BLACKFRIDAY25"
 * }
 *
 * Requer:
 * req.user = {
 *   id: "...",
 *   tenantId: "...",
 *   roles: [...]
 * }
 */
async function redeemCoupon(req, res) {
  const requestId = randomUUID();

  try {
    // Autenticação/autorização deve ter sido executada antes desta rota.
    if (!req.user?.id || !req.user?.tenantId) {
      return sendJson(res, 401, {
        error: 'unauthorized',
        requestId,
      });
    }

    if (!Array.isArray(req.user.roles) ||
        !req.user.roles.includes('billing:write')) {
      return sendJson(res, 403, {
        error: 'forbidden',
        requestId,
      });
    }

    const body = await readJson(req);

    if (
      !body ||
      typeof body.code !== 'string' ||
      body.code.length < 3 ||
      body.code.length > 64
    ) {
      return sendJson(res, 400, {
        error: 'invalid_coupon_code',
        requestId,
      });
    }

    // Normalização previsível, sem aceitar valores arbitrariamente grandes.
    const code = body.code.trim().toUpperCase();

    if (!/^[A-Z0-9_-]+$/.test(code)) {
      return sendJson(res, 400, {
        error: 'invalid_coupon_code',
        requestId,
      });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      /*
       * IMPORTANTE:
       * O tenant é obtido exclusivamente da identidade autenticada.
       * Nunca aceite tenantId no body para decidir qual assinatura alterar.
       */
      const subscriptionResult = await client.query(
        `
        SELECT
          id,
          tenant_id,
          monthly_price_cents,
          status
        FROM subscriptions
        WHERE tenant_id = $1
          AND status = 'active'
        FOR UPDATE
        `,
        [req.user.tenantId]
      );

      if (subscriptionResult.rowCount !== 1) {
        await client.query('ROLLBACK');

        return sendJson(res, 404, {
          error: 'active_subscription_not_found',
          requestId,
        });
      }

      const subscription = subscriptionResult.rows[0];

      /*
       * FOR UPDATE serializa alterações concorrentes na assinatura.
       * A consulta do cupom também ocorre dentro da mesma transação.
       */
      const couponResult = await client.query(
        `
        SELECT
          id,
          code,
          discount_type,
          discount_value,
          max_redemptions,
          redemption_count,
          starts_at,
          expires_at,
          active
        FROM coupons
        WHERE code = $1
          AND active = TRUE
          AND starts_at <= NOW()
          AND (expires_at IS NULL OR expires_at > NOW())
        FOR UPDATE
        `,
        [code]
      );

      if (couponResult.rowCount !== 1) {
        await client.query('ROLLBACK');

        return sendJson(res, 404, {
          error: 'coupon_not_found_or_expired',
          requestId,
        });
      }

      const coupon = couponResult.rows[0];

      if (
        coupon.max_redemptions !== null &&
        coupon.redemption_count >= coupon.max_redemptions
      ) {
        await client.query('ROLLBACK');

        return sendJson(res, 409, {
          error: 'coupon_redemption_limit_reached',
          requestId,
        });
      }

      /*
       * Impede que o mesmo tenant resgate o mesmo cupom duas vezes.
       * Deve existir UNIQUE (tenant_id, coupon_id) em coupon_redemptions.
       */
      const previousRedemption = await client.query(
        `
        SELECT id
        FROM coupon_redemptions
        WHERE tenant_id = $1
          AND coupon_id = $2
        LIMIT 1
        `,
        [req.user.tenantId, coupon.id]
      );

      if (previousRedemption.rowCount > 0) {
        await client.query('ROLLBACK');

        return sendJson(res, 409, {
          error: 'coupon_already_redeemed',
          requestId,
        });
      }

      const originalPrice = Number(subscription.monthly_price_cents);

      if (!Number.isSafeInteger(originalPrice) || originalPrice < 0) {
        throw new Error('Invalid monetary value in database');
      }

      let discountCents;

      if (coupon.discount_type === 'percentage') {
        const percentage = Number(coupon.discount_value);

        if (!Number.isFinite(percentage) ||
            percentage < 0 ||
            percentage > 100) {
          throw new Error('Invalid percentage coupon');
        }

        discountCents = Math.floor(originalPrice * percentage / 100);
      } else if (coupon.discount_type === 'fixed') {
        discountCents = Number(coupon.discount_value);

        if (!Number.isSafeInteger(discountCents) || discountCents < 0) {
          throw new Error('Invalid fixed coupon');
        }
      } else {
        throw new Error('Unsupported coupon type');
      }

      // Nunca permitimos que o desconto gere preço negativo.
      discountCents = Math.min(discountCents, originalPrice);

      const updatedPrice = originalPrice - discountCents;

      /*
       * Registra o resgate e altera a assinatura na MESMA transação.
       * Se qualquer operação falhar, nenhuma alteração é persistida.
       */
      await client.query(
        `
        INSERT INTO coupon_redemptions (
          id,
          coupon_id,
          tenant_id,
          redeemed_by_user_id,
          discount_cents,
          created_at
        )
        VALUES ($1, $2, $3, $4, $5, NOW())
        `,
        [
          randomUUID(),
          coupon.id,
          req.user.tenantId,
          req.user.id,
          discountCents,
        ]
      );

      await client.query(
        `
        UPDATE coupons
        SET redemption_count = redemption_count + 1
        WHERE id = $1
        `,
        [coupon.id]
      );

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
          req.user.tenantId,
        ]
      );

      await client.query('COMMIT');

      return sendJson(res, 200, {
        subscription: {
          id: subscription.id,
          monthlyPriceCents: updatedPrice,
          monthlyPrice: (updatedPrice / 100).toFixed(2),
          currency: 'BRL',
        },
        coupon: {
          code: coupon.code,
          discountCents,
        },
        requestId,
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    /*
     * Não expor stack trace, SQL, nomes de tabelas ou detalhes internos
     * ao cliente.
     */
    console.error('coupon redemption failed', {
      requestId,
      error,
    });

    return sendJson(res, 500, {
      error: 'internal_server_error',
      requestId,
    });
  }
}

/**
 * Helpers mínimos para manter o exemplo independente de framework.
 */

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);

  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });

  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const MAX_BODY_SIZE = 8 * 1024; // 8 KB
    let size = 0;
    let data = '';

    req.setEncoding('utf8');

    req.on('data', chunk => {
      size += Buffer.byteLength(chunk);

      if (size > MAX_BODY_SIZE) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }

      data += chunk;
    });

    req.on('end', () => {
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', reject);
  });
}

/**
 * Exemplo de autenticação/roteamento.
 *
 * Em produção, req.user deve ser criado por middleware que valide
 * uma sessão/JWT/OIDC antes de chegar à função acima.
 */
const server = http.createServer(async (req, res) => {
  if (
    req.method === 'POST' &&
    req.url === '/api/v1/billing/coupons/redeem'
  ) {
    return redeemCoupon(req, res);
  }

  return sendJson(res, 404, {
    error: 'not_found',
  });
});

server.listen(process.env.PORT || 3000);
