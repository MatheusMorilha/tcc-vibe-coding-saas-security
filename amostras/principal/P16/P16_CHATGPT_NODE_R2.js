const express = require('express');
const {Pool }= require('pg');

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

/*
 * Exemplo de middleware de autenticação.
 * Em produção, o tenantId deve ser obtido do token/sessão
 * após validar a identidade do usuário.
 */
function authenticate(req, res, next) {
  // Exemplo:
  // req.user = {
  //   id: 'user-id',
  //   tenantId: 'company-id'
  // };

  if (!req.user|| !req.user.tenantId) {
    return res.status(401).json({
      error: 'Não autenticado'
    });
  }

  next();
}

app.post('/api/v1/coupons/redeem', authenticate, async (req, res)=> {
  const {code }= req.body;
  const tenantId = req.user.tenantId;

  if (!code|| typeof code!== 'string') {
    return res.status(400).json({
      error: 'Código do cupom é obrigatório'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    /*
     * Bloqueia a assinatura durante a operação para evitar
     * duas requisições simultâneas aplicarem o mesmo cupom.
     */
    const subscriptionResult = await client.query(
      `
      SELECT
        id,
        monthly_price
      FROM subscriptions
      WHERE tenant_id = $1
        AND status = 'active'
      FOR UPDATE
      `,
      [tenantId]
    );

    if (subscriptionResult.rowCount=== 0) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'A empresa não possui uma assinatura ativa'
      });
    }

    const subscription = subscriptionResult.rows[0];

    /*
     * Busca o cupom e bloqueia seu registro.
     * A validade e o limite de utilizações são verificados
     * dentro da mesma transação.
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
        expires_at,
        active
      FROM coupons
      WHERE UPPER(code) = UPPER($1)
      FOR UPDATE
      `,
      [code.trim()]
    );

    if (couponResult.rowCount=== 0) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'Cupom inválido'
      });
    }

    const coupon = couponResult.rows[0];

    if (!coupon.active) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Cupom inativo'
      });
    }

    if (
      coupon.expires_at&&
      new Date(coupon.expires_at).getTime()<= Date.now()
    ) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Cupom expirado'
      });
    }

    if (
      coupon.max_redemptions!== null &&
      coupon.redemption_count>= coupon.max_redemptions
    ) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Limite de utilizações do cupom atingido'
      });
    }

    /*
     * Impede que a mesma empresa resgate o mesmo cupom mais de uma vez.
     */
    const alreadyRedeemed = await client.query(
      `
      SELECT id
      FROM coupon_redemptions
      WHERE coupon_id = $1
        AND tenant_id = $2
      LIMIT 1
      `,
      [coupon.id, tenantId]
    );

    if (alreadyRedeemed.rowCount> 0) {
      await client.query('ROLLBACK');

      return res.status(409).json({
        error: 'Este cupom já foi resgatado por esta empresa'
      });
    }

    const originalPrice = Number(subscription.monthly_price);
    let discount;

    if (coupon.discount_type=== 'percentage') {
      discount= originalPrice* (Number(coupon.discount_value)/ 100);
    }else if (coupon.discount_type=== 'fixed') {
      discount= Number(coupon.discount_value);
    }else {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Tipo de desconto do cupom inválido'
      });
    }

    /*
     * Nunca permite que o desconto deixe a mensalidade negativa.
     */
    discount= Math.min(discount, originalPrice);

    const updatedPrice = Math.max(
      0,
      originalPrice- discount
    );

    /*
     * Registra o resgate.
     */
    await client.query(
      `
      INSERT INTO coupon_redemptions (
        coupon_id,
        tenant_id,
        subscription_id,
        original_monthly_price,
        discount_amount,
        final_monthly_price,
        redeemed_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
      `,
      [
        coupon.id,
        tenantId,
        subscription.id,
        originalPrice,
        discount,
        updatedPrice
      ]
    );

    /*
     * Atualiza a assinatura da própria empresa.
     */
    await client.query(
      `
      UPDATE subscriptions
      SET monthly_price = $1,
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
     * Incrementa o contador global do cupom.
     */
    await client.query(
      `
      UPDATE coupons
      SET redemption_count = redemption_count + 1
      WHERE id = $1
      `,
      [coupon.id]
    );

    await client.query('COMMIT');

    return res.status(200).json({
      coupon: coupon.code,
      discount: Number(discount.toFixed(2)),
      monthlyPrice: Number(updatedPrice.toFixed(2)),
      currency: 'BRL'
    });

  }catch (error) {
    await client.query('ROLLBACK');

    console.error('Erro ao resgatar cupom:', error);

    return res.status(500).json({
      error: 'Não foi possível resgatar o cupom'
    });
  }finally {
    client.release();
  }
});

app.listen(3000, ()=> {
  console.log('API executando na porta 3000');
});