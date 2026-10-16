import express from 'express';
import helmet from 'helmet';
import webhookRouter from './routes/webhook.routes.js';

const app = express();

// A05: Cabeçalhos seguros
app.use(helmet());

// Preserva o buffer bruto especificamente para a rota de webhook
app.use(
  '/api/v1/webhooks',
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
    limit: '256kb', // Limite contra Denial of Service por payloads gigantes
  })
);

// Demais rotas da aplicação
app.use(express.json());

app.use('/api/v1/webhooks', webhookRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serviço de faturamento escutando na porta ${PORT}`);
});

import crypto from 'crypto';
import { z } from 'zod';
import { prisma } from '../lib/prisma.js'; // Instância do cliente do banco de dados

// A03: Schema de validação estrito contra injeção e dados corrompidos
const WebhookEventSchema = z.object({
  id: z.string().min(1),
  event: z.enum([
    'invoice.payment_succeeded',
    'invoice.payment_failed',
    'invoice.canceled'
  ]),
  created: z.number().int(),
  data: z.object({
    invoiceId: z.string().uuid(),
    tenantId: z.string().uuid(),
    amountPaid: z.number().nonnegative(),
    currency: z.string().length(3),
  }),
});

/**
 * Validação de integridade do Webhook contra Timing Attacks
 */
function verifyWebhookSignature(rawBody, signatureHeader, secret){
  if (!rawBody || !signatureHeader || !secret) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');

  const providedSignature = Buffer.from(signatureHeader, 'utf-8');
  const generatedSignature = Buffer.from(expectedSignature, 'utf-8');

  if (providedSignature.length !== generatedSignature.length) {
    return false;
  }

  // A02: Comparação de tempo constante para prevenir timing attacks
  return crypto.timingSafeEqual(providedSignature, generatedSignature);
}

export async function handlePaymentGatewayWebhook(req, res){
  const signature = req.headers['x-gateway-signature'];
  const webhookSecret = process.env.PAYMENT_GATEWAY_WEBHOOK_SECRET;

  // 1. A02 / A08: Verificação criptográfica de autenticidade
  if (!verifyWebhookSignature(req.rawBody, signature, webhookSecret)) {
    console.warn('[SECURITY] Tentativa de webhook rejeitada: assinatura inválida.');
    return res.status(401).json({ error: 'Assinatura inválida.' });
  }

  // 2. A03: Sanitização e validação de schema
  const parseResult = WebhookEventSchema.safeParse(req.body);
  if (!parseResult.success) {
    console.warn('[VALIDATION] Formato de payload inválido:', parseResult.error.flatten());
    return res.status(400).json({ error: 'Payload inconsistente.' });
  }

  const { id: eventId, event: eventType, data } = parseResult.data;
  const { tenantId, invoiceId, amountPaid } = data;

  try {
    // 3. Execução Atômica e Isolada por Tenant
    await prisma.$transaction(async (tx) => {
      // A08: Idempotência - previne reprocessamento acidental ou malicioso
      const existingEvent = await tx.processedWebhookEvent.findUnique({
        where: { eventId },
      });

      if (existingEvent) {
        return; // Evento já processado; saímos da transação sem erros
      }

      // A01: Defesa contra IDOR/Quebra de isolamento multilocatário
      // O filtro OBRIGATORIAMENTE combina id e tenantId
      const invoice = await tx.invoice.findFirst({
        where: {
          id: invoiceId,
          tenantId: tenantId,
        },
      });

      if (!invoice) {
        throw new Error(`INVOICE_NOT_FOUND_FOR_TENANT`);
      }

      // 4. Mapeamento de Estados
      let newInvoiceStatus;
      let newSubscriptionStatus;

      switch (eventType) {
        case 'invoice.payment_succeeded':
          newInvoiceStatus = 'PAID';
          newSubscriptionStatus = 'ACTIVE';
          break;

        case 'invoice.payment_failed':
          newInvoiceStatus = 'OVERDUE';
          newSubscriptionStatus = 'PAST_DUE';
          break;

        case 'invoice.canceled':
          newInvoiceStatus = 'CANCELED';
          newSubscriptionStatus = 'CANCELED';
          break;
      }

      // 5. Atualização da Fatura assegurando o contexto do locatário
      await tx.invoice.update({
        where: {
          id: invoice.id,
          tenantId: tenantId, // Garante que a cláusula WHERE restrinja o tenant
        },
        data: {
          status: newInvoiceStatus,
          paidAt: newInvoiceStatus === 'PAID' ? new Date() : null,
          amountPaid: newInvoiceStatus === 'PAID' ? amountPaid : invoice.amountPaid,
        },
      });

      // 6. Atualização da Assinatura vinculada ao Locatário
      await tx.subscription.update({
        where: {
          id: invoice.subscriptionId,
          tenantId: tenantId,
        },
        data: {
          status: newSubscriptionStatus,
        },
      });

      // 7. Registro do evento para garantia de idempotência
      await tx.processedWebhookEvent.create({
        data: {
          eventId,
          eventType,
          tenantId,
          processedAt: new Date(),
        },
      });
    });

    // A09: Log estruturado de auditoria sem expor segredos
    console.info(`[AUDIT] Fatura processada com sucesso. Evento: ${eventId}, Tenant: ${tenantId}, Status: ${eventType}`);

    return res.status(200).json({ received: true });
  } catch (error) {
    if (error.message === 'INVOICE_NOT_FOUND_FOR_TENANT') {
      console.error(`[VIOLATION/ERROR] Inconsistência de locatário ou fatura inexistente. Invoice: ${invoiceId}, Tenant: ${tenantId}`);
      // Retorna 422 para não travar a fila do gateway com erros 500 em caso de inconsistência de chaves
      return res.status(422).json({ error: 'Fatura não encontrada para o locatário informado.' });
    }

    // A09: Erro interno registrado de forma segura
    console.error('[FATAL] Erro ao processar transação de webhook:', error.message);
    return res.status(500).json({ error: 'Erro interno ao processar evento.' });
  }
}

import { Router } from 'express';
import { handlePaymentGatewayWebhook } from '../controllers/webhook.controller.js';

const router = Router();

// Endpoint exposto para recebimento das notificações do gateway
router.post('/payment-events', handlePaymentGatewayWebhook);

export default router;