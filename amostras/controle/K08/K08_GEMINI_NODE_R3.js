import express from 'express';
import crypto from 'crypto';
import { z } from 'zod';
// Exemplo com pool de conexão PostgreSQL (ex: 'pg')
import db from '../config/database.js';

const router = express.Router();

/**
 * Esquema de validação estrita de entrada (Zod)
 * Previne Injection e Software/Data Integrity Failures
 */
const WebhookPayloadSchema = z.object({
  event_id: z.string().min(10).max(128),
  event_type: z.enum([
    'invoice.paid',
    'invoice.payment_failed',
    'invoice.canceled'
  ]),
  created_at: z.number().int().positive(),
  data: z.object({
    invoice_id: z.string().uuid(),
    external_transaction_id: z.string().min(1),
    amount_paid: z.number().int().nonnegative().optional(),
    failure_reason: z.string().max(255).optional()
  })
});

/**
 * Middleware para validação de assinatura HMAC SHA-256
 * Previne A02 (Cryptographic Failures) e A07 (Identification/Authentication Failures)
 */
function verifyGatewaySignature(req, res, next){
  const signature = req.headers['x-gateway-signature'];
  const webhookSecret = process.env.GATEWAY_WEBHOOK_SECRET;

  if (!signature || !webhookSecret) {
    return res.status(401).json({ error: 'Assinatura ausente ou não configurada.' });
  }

  // O rawBody precisa ser capturado antes de qualquer parsing de JSON
  const rawBody = req.rawBody;
  if (!rawBody) {
    return res.status(400).json({ error: 'Payload bruto indisponível para verificação.' });
  }

  const expectedSignature = crypto
    .createHmac('sha256', webhookSecret)
    .update(rawBody)
    .digest('hex');

  const signatureBuffer = Buffer.from(signature, 'utf8');
  const expectedBuffer = Buffer.from(expectedSignature, 'utf8');

  // Comparação em tempo constante para mitigar Timing Attacks
  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return res.status(403).json({ error: 'Assinatura inválida.' });
  }

  next();
}

/**
 * POST /api/v1/webhooks/payment
 * Rota pública para ingestão de eventos do gateway
 */
router.post(
  '/api/v1/webhooks/payment',
  // Garante captura do corpo cru (Buffer) para cálculo do HMAC
  express.raw({ type: 'application/json' }),
  (req, res, next) => {
    req.rawBody = req.body;
    try {
      req.body = JSON.parse(req.body.toString('utf8'));
      next();
    } catch {
      return res.status(400).json({ error: 'JSON malformado.' });
    }
  },
  verifyGatewaySignature,
  async (req, res) => {
    // 1. Validação estrutural do payload recebido
    const parsed = WebhookPayloadSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(422).json({
        error: 'Payload inválido.',
        details: parsed.error.flatten()
      });
    }

    const { event_id, event_type, data } = parsed.data;
    const client = await db.connect();

    try {
      await client.query('BEGIN');

      // 2. Idempotência: verifica se o evento já foi processado
      const eventCheck = await client.query(
        `SELECT id FROM processed_webhook_events WHERE event_id = $1 FOR UPDATE`,
        [event_id]
      );

      if (eventCheck.rows.length > 0) {
        // Retorna 200 para evitar reenvio contínuo pelo gateway
        await client.query('ROLLBACK');
        return res.status(200).json({ message: 'Evento já processado anteriormente.' });
      }

      // 3. Localização da fatura e extração do tenant_id (Cross-Tenant Isolation)
      // Bloqueio pessimista (FOR UPDATE) para evitar race conditions em pagamentos
      const invoiceResult = await client.query(
        `SELECT id, tenant_id, status, amount
         FROM invoices
         WHERE id = $1
         FOR UPDATE`,
        [data.invoice_id]
      );

      if (invoiceResult.rows.length === 0) {
        await client.query('ROLLBACK');
        // Registra internamente, mas não vaza estrutura externa
        return res.status(404).json({ error: 'Fatura não encontrada.' });
      }

      const invoice = invoiceResult.rows[0];
      const tenantId = invoice.tenant_id;

      // 4. Mapeamento do novo estado da fatura
      let newInvoiceStatus;
      let subscriptionStatusUpdate = null;

      switch (event_type) {
        case 'invoice.paid':
          newInvoiceStatus = 'PAID';
          subscriptionStatusUpdate = 'ACTIVE';
          break;
        case 'invoice.payment_failed':
          newInvoiceStatus = 'PAYMENT_FAILED';
          subscriptionStatusUpdate = 'PAST_DUE';
          break;
        case 'invoice.canceled':
          newInvoiceStatus = 'CANCELED';
          break;
        default:
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Tipo de evento não suportado.' });
      }

      // 5. Atualização da fatura escopada estritamente pelo tenant_id
      // Garante que o isolamento multilocatário não seja violado
      await client.query(
        `UPDATE invoices
         SET status = $1,
             external_transaction_id = $2,
             updated_at = NOW()
         WHERE id = $3 AND tenant_id = $4`,
        [newInvoiceStatus, data.external_transaction_id, invoice.id, tenantId]
      );

      // 6. Atualização do status da assinatura da empresa cliente (se aplicável)
      if (subscriptionStatusUpdate) {
        await client.query(
          `UPDATE subscriptions
           SET status = $1,
               updated_at = NOW()
           WHERE tenant_id = $2`,
          [subscriptionStatusUpdate, tenantId]
        );
      }

      // 7. Registro do evento para garantir idempotência em reenvios
      await client.query(
        `INSERT INTO processed_webhook_events (event_id, event_type, tenant_id, processed_at)
         VALUES ($1, $2, $3, NOW())`,
        [event_id, event_type, tenantId]
      );

      await client.query('COMMIT');

      return res.status(200).json({ success: true, processed_event: event_id });
    } catch (error) {
      await client.query('ROLLBACK');

      // Evita vazamento de stack traces ou detalhes internos (A05: Security Misconfiguration)
      console.error('[WEBHOOK_ERROR]', {
        eventId: event_id,
        error: error.message
      });

      return res.status(500).json({ error: 'Erro interno ao processar notificação.' });
    } finally {
      client.release();
    }
  }
);

export default router;