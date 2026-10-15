const express = require('express');
const crypto = require('crypto');
const app = express();

// IMPORTANTE: Para verificação de assinatura em webhooks, precisamos do payload bruto (raw body).
// Certifique-se de usar express.json() com suporte a raw body na rota do webhook.
app.post('/api/v1/webhooks/payment', express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}), async (req, res) => {
  const signature = req.headers['x-signature'] || req.headers['stripe-signature'];
  const webhookSecret = process.env.PAYMENT_WEBHOOK_SECRET;

  // 1. Validação da Assinatura do Webhook (Segurança)
  if (!isValidSignature(req.rawBody, signature, webhookSecret)) {
    console.error('[Webhook Error] Assinatura inválida');
    return res.status(401).json({ error: 'Assinatura inválida' });
  }

  const event = req.body;

  try {
    // 2. Roteamento do evento recebido
    switch (event.type) {
      case 'invoice.payment_succeeded':
        await handlePaymentSucceeded(event.data);
        break;

      case 'invoice.payment_failed':
        await handlePaymentFailed(event.data);
        break;

      case 'subscription.canceled':
        await handleSubscriptionCanceled(event.data);
        break;

      default:
        console.log(`[Webhook Info] Evento não monitorado: ${event.type}`);
    }

    // Retorna 200 OK para confirmar ao Gateway que o evento foi processado
    return res.status(200).json({ received: true });
  } catch (error) {
    console.error(`[Webhook Error] Falha ao processar evento ${event.type}:`, error);
    // Retorna 500 para que o gateway tente reenviar a notificação (retry)
    return res.status(500).json({ error: 'Erro interno ao processar notificação' });
  }
});

/**
 * Valida a assinatura HMAC SHA256 do Gateway de Pagamento
 */
function isValidSignature(rawBody, signature, secret){
  if (!signature || !secret || !rawBody) return false;

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');

  // Utiliza timingSafeEqual para evitar ataques de timing
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  } catch {
    return false;
  }
}