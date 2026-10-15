const http = require('http');

const PORT = process.env.PORT || 3000;

// Exemplo de interface de banco.
// Substitua pela implementação real (PostgreSQL, MySQL etc.).
const db = require('./db');

/**
 * POST /api/coupons/redeem
 *
 * Headers:
 *   Authorization: Bearer <token>
 *
 * Body:
 *   {
 *     "code": "PROMO20"
 *   }
 *
 * Response:
 *   {
 *     "coupon": "PROMO20",
 *     "discountPercent": 20,
 *     "originalMonthlyPrice": 100,
 *     "discountAmount": 20,
 *     "updatedMonthlyPrice": 80
 *   }
 */
async function redeemCoupon(req, res) {
  try {
    const user = await authenticate(req);

    if (!user) {
      return sendJson(res, 401, {
        error: 'Não autenticado'
      });
    }

    const body = await parseJsonBody(req);
    const code = typeof body.code=== 'string'
      ? body.code.trim().toUpperCase()
      : '';

    if (!code) {
      return sendJson(res, 400, {
        error: 'Código do cupom é obrigatório'
      });
    }

    /*
     * IMPORTANTE:
     * O tenant_id vem da sessão/token autenticado,
     * nunca do body enviado pelo cliente.
     */
    const tenantId = user.tenantId;

    await db.beginTransaction();

    try {
      // Bloqueia o cupom durante a transação para evitar
      // dois resgates simultâneos ultrapassarem os limites.
      const coupon = await db.queryOne(
        `
        SELECT
          id,
          code,
          discount_percent,
          max_redemptions,
          redemption_count,
          expires_at,
          active
        FROM coupons
        WHERE code = ?
        FOR UPDATE
        `,
        [code]
      );

      if (!coupon) {
        await db.rollback();

        return sendJson(res, 404, {
          error: 'Cupom inválido'
        });
      }

      if (!coupon.active) {
        await db.rollback();

        return sendJson(res, 400, {
          error: 'Cupom inativo'
        });
      }

      if (
        coupon.expires_at&&
        new Date(coupon.expires_at).getTime()< Date.now()
      ) {
        await db.rollback();

        return sendJson(res, 400, {
          error: 'Cupom expirado'
        });
      }

      if (
        coupon.max_redemptions!== null &&
        coupon.redemption_count>= coupon.max_redemptions
      ) {
        await db.rollback();

        return sendJson(res, 400, {
          error: 'Limite de resgates do cupom atingido'
        });
      }

      /*
       * Impede que a mesma empresa resgate o mesmo cupom novamente.
       */
      const existingRedemption = await db.queryOne(
        `
        SELECT id
        FROM coupon_redemptions
        WHERE tenant_id = ?
          AND coupon_id = ?
        LIMIT 1
        `,
        [tenantId, coupon.id]
      );

      if (existingRedemption) {
        await db.rollback();

        return sendJson(res, 409, {
          error: 'Este cupom já foi resgatado pela empresa'
        });
      }

      /*
       * Busca a assinatura pertencente EXPLICITAMENTE ao tenant
       * autenticado.
       */
      const subscription = await db.queryOne(
        `
        SELECT
          id,
          monthly_price
        FROM subscriptions
        WHERE tenant_id = ?
          AND status = 'active'
        LIMIT 1
        FOR UPDATE
        `,
        [tenantId]
      );

      if (!subscription) {
        await db.rollback();

        return sendJson(res, 400, {
          error: 'A empresa não possui uma assinatura ativa'
        });
      }

      const originalPrice = Number(subscription.monthly_price);
      const discountPercent = Number(coupon.discount_percent);

      if (
        !Number.isFinite(originalPrice)||
        !Number.isFinite(discountPercent)||
        discountPercent< 0 ||
        discountPercent> 100
      ) {
        await db.rollback();

        return sendJson(res, 500, {
          error: 'Dados de cobrança inválidos'
        });
      }

      const discountAmount = Number(
        (originalPrice* discountPercent/ 100).toFixed(2)
      );

      const updatedPrice = Number(
        Math.max(0, originalPrice- discountAmount).toFixed(2)
      );

      /*
       * Registra o resgate e atualiza a assinatura
       * na mesma transação.
       */
      await db.execute(
        `
        INSERT INTO coupon_redemptions (
          coupon_id,
          tenant_id,
          discount_percent,
          discount_amount,
          created_at
        )
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        `,
        [
          coupon.id,
          tenantId,
          discountPercent,
          discountAmount
        ]
      );

      await db.execute(
        `
        UPDATE coupons
        SET redemption_count = redemption_count + 1
        WHERE id = ?
        `,
        [coupon.id]
      );

      await db.execute(
        `
        UPDATE subscriptions
        SET monthly_price = ?
        WHERE id = ?
          AND tenant_id = ?
        `,
        [
          updatedPrice,
          subscription.id,
          tenantId
        ]
      );

      await db.commit();

      return sendJson(res, 200, {
        coupon: coupon.code,
        discountPercent,
        originalMonthlyPrice: originalPrice,
        discountAmount,
        updatedMonthlyPrice: updatedPrice
      });

    }catch (error) {
      await db.rollback();
      throw error;
    }

  }catch (error) {
    console.error(error);

    return sendJson(res, 500, {
      error: 'Erro interno do servidor'
    });
  }
}


/*
 * Autenticação simplificada apenas para demonstrar o fluxo.
 * Em produção, valide JWT/session e obtenha o tenantId
 * exclusivamente das credenciais autenticadas.
 */
async function authenticate(req) {
  const authorization = req.headers.authorization;

  if (!authorization) {
    return null;
  }

  // Exemplo:
  // const token = authorization.replace('Bearer ', '');
  // return await verifyToken(token);

  return {
    userId: 123,
    tenantId: 456
  };
}


function parseJsonBody(req) {
  return new Promise((resolve, reject)=> {
    let data= '';

    req.on('data', chunk=> {
      data+= chunk;

      // Proteção básica contra payloads excessivamente grandes.
      if (data.length > 1024 * 1024) {
        reject(new Error('Payload muito grande'));
        req.destroy();
      }
    });

    req.on('end', ()=> {
      try {
        resolve(data? JSON.parse(data): {});
      }catch {
        reject(new Error('JSON inválido'));
      }
    });

    req.on('error', reject);
  });
}


function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8'
  });

  res.end(JSON.stringify(payload));
}


const server = http.createServer(async (req, res)=> {
  if (
    req.method=== 'POST' &&
    req.url=== '/api/coupons/redeem'
  ) {
    return redeemCoupon(req, res);
  }

  sendJson(res, 404, {
    error: 'Rota não encontrada'
  });
});


server.listen(PORT, ()=> {
  console.log(`API executando na porta${PORT}`);
});