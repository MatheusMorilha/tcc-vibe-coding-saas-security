const express = require('express');
const crypto = require('crypto');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();

// O gateway precisa enviar o body em formato RAW para verificação de assinatura
app.use(express.raw({ type: 'application/json' }));

/**
 * Valida a assinatura enviada pelo gateway de pagamento para garantir a autenticidade da requisição.
 */
function verifyWebhookSignature(payload, signatureHeader, secret){
  if (!signatureHeader || !secret) return false;

  const hmac = crypto.createHmac('sha256', secret);
  const expectedSignature = hmac.update(payload).digest('hex');

  return crypto.timingSafeEqual(
    Buffer.from(signatureHeader),
    Buffer.from(expectedSignature)
  );
}

/**
 * POST /api/v1/webhooks/payment
 * Rota para recepção e processamento de eventos do gateway de pagamento.
 */
app.post('/api/v1/webhooks/payment', async (req, res) => {
  const signature = req.headers['x-gateway-signature'];
  const webhookSecret = process.env.PAYMENT_WEBHOOK_SECRET;

  // 1. Validação de Segurança
  if (!verifyWebhookSignature(req.body, signature, webhookSecret)) {
    return res.status(401).json({ error: 'Assinatura do webhook inválida.' });
  }

  let event;
  try {
    event = JSON.parse(req.body.toString());
  } catch (err) {
    return res.status(400).json({ error: 'Payload JSON inválido.' });
  }

  const { event_id, event_type, data } = event;
  const { invoice_id, tenant_id, status, paid_at } = data;

  try {
    // 2. Processamento em Transação (Garante Idempotência e Isolamento do Tenant)
    await prisma.$transaction(async (tx) => {
      // Verifica se o evento já foi processado anteriormente (Idempotência)
      const processedEvent = await tx.processedWebhook.findUnique({
        where: { eventId: event_id },
      });

      if (processedEvent) {
        // Evento já processado; encerra sem duplicar ações
        return;
      }

      // Mapeamento dos status do gateway para o domínio do SaaS
      const statusMap = {
        'payment.succeeded': 'PAID',
        'payment.failed': 'FAILED',
        'charge.refunded': 'REFUNDED',
      };

      const newStatus = statusMap[event_type];

      if (newStatus) {
        // Atualiza a fatura garantindo o isolamento pelo tenant_id
        const invoice = await tx.invoice.updateMany({
          where: {
            id: invoice_id,
            tenantId: tenant_id, // Garante que a fatura pertence à empresa/tenant correta
          },
          data: {
            status: newStatus,
            paidAt: newStatus === 'PAID' ? new Date(paid_at || Date.now()) : null,
            updatedAt: new Date(),
          },
        });

        if (invoice.count === 0) {
          throw new Error(`Fatura ${invoice_id} não encontrada para o tenant ${tenant_id}`);
        }

        // Se o pagamento for confirmado, atualiza o status do plano da assinatura do tenant
        if (newStatus === 'PAID') {
          await tx.tenantSubscription.update({
            where: { tenantId: tenant_id },
            data: { status: 'ACTIVE', lastBillingDate: new Date() },
          });
        }
      }

      // Registra o evento como processado
      await tx.processedWebhook.create({
        data: {
          eventId: event_id,
          eventType: event_type,
          tenantId: tenant_id,
          processedAt: new Date(),
        },
      });
    });

    // Retorna 200 rápido para o gateway não tentar reenviar
    return res.status(200).json({ received: true });

  } catch (error) {
    console.error(`[Webhook Error] Evento ${event_id}:`, error.message);

    // Retorna 500 para que o gateway realize nova tentativa (retry) em caso de erro de infra/banco
    return res.status(500).json({ error: 'Falha interna ao processar evento de pagamento.' });
  }
});