const http = require('http');
const crypto = require('crypto');

/*
 * Exemplo de persistência.
 * Em uma aplicação real, estas operações seriam substituídas por queries
 * ao banco de dados usando transação.
 */
const db = {
  companies: new Map([
    [
      'company-1',
      {
        id: 'company-1',
        plan: {
          monthlyPrice: 10000, // valor em centavos: R$ 100,00
          couponId: null,
          monthlyPriceAfterDiscount: 10000
        }
      }
    ]
  ]),

  coupons: new Map([
    [
      'PROMO20',
      {
        id: 'coupon-1',
        code: 'PROMO20',
        type: 'percentage',
        value: 20,
        active: true,
        expiresAt: '2026-12-31T23:59:59.000Z',
        maxRedemptions: 100,
        redemptions: 0
      }
    ]
  ])
};

/*
 * Simulação de autenticação.
 *
 * Em produção, o middleware de autenticação deve validar o token/sessão
 * e fornecer o tenantId associado ao usuário autenticado.
 */
function authenticate(request) {
  // Exemplo: usuário autenticado pertence à company-1.
  return {
    userId: 'user-123',
    tenantId: 'company-1'
  };
}

function parseJsonBody(request) {
  return new Promise((resolve, reject)=> {
    let body= '';

    request.on('data', chunk=> {
      body+= chunk;

      // Limite simples para evitar payloads excessivamente grandes.
      if (body.length > 10_000) {
        reject(new Error('Payload muito grande'));
        request.destroy();
      }
    });

    request.on('end', ()=> {
      try {
        resolve(body? JSON.parse(body): {});
      }catch {
        reject(new Error('JSON inválido'));
      }
    });

    request.on('error', reject);
  });
}

function calculateDiscount(monthlyPrice, coupon) {
  if (coupon.type=== 'percentage') {
    return Math.round(monthlyPrice* (coupon.value/ 100));
  }

  if (coupon.type=== 'fixed') {
    return Math.min(coupon.value, monthlyPrice);
  }

  throw new Error('Tipo de cupom inválido');
}

function sendJson(response, statusCode, data) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8'
  });

  response.end(JSON.stringify(data));
}

const server = http.createServer(async (request, response)=> {
  if (
    request.method!== 'POST' ||
    request.url!== '/api/v1/subscription/coupon'
  ) {
    return sendJson(response, 404, {
      error: 'Rota não encontrada'
    });
  }

  try {
    /*
     * 1. Identifica o tenant pelo contexto autenticado.
     *
     * Não utilizamos tenantId vindo do body da requisição.
     */
    const auth = authenticate(request);

    if (!auth|| !auth.tenantId) {
      return sendJson(response, 401, {
        error: 'Não autenticado'
      });
    }

    /*
     * 2. Valida o payload.
     */
    const body = await parseJsonBody(request);

    if (
      typeof body.couponCode!== 'string' ||
      body.couponCode.trim().length === 0
    ) {
      return sendJson(response, 400, {
        error: 'couponCode é obrigatório'
      });
    }

    const couponCode = body.couponCode.trim().toUpperCase();

    /*
     * 3. Busca a empresa exclusivamente pelo tenant autenticado.
     */
    const company = db.companies.get(auth.tenantId);

    if (!company) {
      return sendJson(response, 404, {
        error: 'Empresa não encontrada'
      });
    }

    /*
     * 4. Busca e valida o cupom.
     */
    const coupon = db.coupons.get(couponCode);

    if (!coupon|| !coupon.active) {
      return sendJson(response, 400, {
        error: 'Cupom inválido ou inativo'
      });
    }

    if (
      coupon.expiresAt&&
      new Date(coupon.expiresAt).getTime()< Date.now()
    ) {
      return sendJson(response, 400, {
        error: 'Cupom expirado'
      });
    }

    if (
      coupon.maxRedemptions!== null &&
      coupon.redemptions>= coupon.maxRedemptions
    ) {
      return sendJson(response, 400, {
        error: 'Limite de resgates do cupom atingido'
      });
    }

    /*
     * 5. Impede a aplicação repetida do mesmo cupom.
     */
    if (company.plan.couponId=== coupon.id) {
      return sendJson(response, 409, {
        error: 'Cupom já aplicado à assinatura'
      });
    }

    /*
     * 6. Calcula o novo valor.
     *
     * Os valores monetários são armazenados em centavos para evitar
     * problemas de precisão de ponto flutuante.
     */
    const monthlyPrice = company.plan.monthlyPrice;
    const discount = calculateDiscount(monthlyPrice, coupon);

    const updatedMonthlyPrice = monthlyPrice- discount;

    /*
     * 7. Atualiza a assinatura.
     *
     * Em produção, esta parte deve ocorrer em uma transação no banco,
     * garantindo atomicidade entre a atualização da assinatura e o
     * incremento de redemptions.
     */
    company.plan.couponId= coupon.id;
    company.plan.monthlyPriceAfterDiscount= updatedMonthlyPrice;

    coupon.redemptions+= 1;

    /*
     * 8. Retorna somente informações necessárias ao cliente.
     */
    return sendJson(response, 200, {
      success: true,
      subscription: {
        monthlyPrice: monthlyPrice,
        discount: discount,
        monthlyPriceAfterDiscount: updatedMonthlyPrice,
        currency: 'BRL'
      },
      coupon: {
        code: coupon.code,
        type: coupon.type,
        value: coupon.value
      }
    });
  }catch (error) {
    console.error(error);

    return sendJson(response, 500, {
      error: 'Erro interno do servidor'
    });
  }
});

server.listen(3000, ()=> {
  console.log('API executando em http://localhost:3000');
});