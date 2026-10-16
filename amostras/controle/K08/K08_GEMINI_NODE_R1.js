import express from 'express';
import crypto from 'crypto';
import { z } from 'zod';
import rateLimit from 'express-rate-limit';

const router = express.Router();

// 1. Limitação de Taxa (OWASP A04/A05 - Prevenção contra DoS e Brute Force)
const webhookLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutos
  max: 300,
  message: { error: 'Taxa de requisições excedida.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// 2. Validação de Schema do Payload (OWASP A03/A04 - Validação de Entrada)
const webhookPayloadSchema = z.object({
  id: z.string().min(1),
  event: z.enum(['invoice.paid', 'invoice.payment_failed']),
  created_at: z.number().int().positive(),
  data: z.object({
    invoice_id: z.string().uuid(),
    tenant_id: z.string().uuid(),
    amount_paid: z.number().nonnegative().optional(),
    paid_at: z.string().datetime().optional(),
  }),
});

/**
 * Validação segura de assinatura HMAC (OWASP A02 - Cryptographic Failures)
 * Previne ataques de timing com crypto.timingSafeEqual
 */
function verifyWebhookSignature(payloadRaw, signatureHeader, secret){
  if (!signatureHeader || !secret) {
    return false;
  }

  // Espera formato: t=timestamp,v1=hash_hexadecimal
  const parts = Object.fromEntries(
    signatureHeader.split(',').map((part) => part.trim().split('='))
  );

  const timestamp = parts.t;
  const signature = parts.v1;

  if (!timestamp || !signature) {
    return false;
  }

  // Prevenção contra Replay Attack: rejeita eventos com mais de 5 minutos de diferença
  const currentTime = Math.floor(Date.now() / 1000);
  if (Math.abs(currentTime - parseInt(timestamp, 10)) > 300) {
    return false;
  }

  const signedPayload = `${timestamp}.${payloadRaw}`;
  const computedHash = crypto
    .createHmac('sha256', secret)
    .update(signedPayload, 'utf8')
    .digest('hex');

  const signatureBuffer = Buffer.from(signature, 'utf8');
  const computedBuffer = Buffer.from(computedHash, 'utf8');

  if (signatureBuffer.length !== computedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(signatureBuffer, computedBuffer);
}

/**
 * Rota do Webhook
 * Importante: Requer express.raw({ type: 'application/json' }) para validar o HMAC intacto.
 */
router.post(
  '/webhooks/payments',
  webhookLimiter,
  express.raw({ type: 'application/json', limit: '256kb' }),
  async (req, res) => {
    const rawBody = req.body.toString('utf8');
    const signature = req.headers['x-signature'];
    const webhookSecret = process.env.PAYMENT_GATEWAY_WEBHOOK_SECRET;

    // 1. Verificação Criptográfica de Origem
    if (!verifyWebhookSignature(rawBody, signature, webhookSecret)) {
      // Log com severidade de segurança (evite logar credenciais ou dados sensíveis)
      console.warn('[Security] Tentativa de webhook com assinatura inválida ou expirada.');
      return res.status(401).json({ error: 'Assinatura inválida.' });
    }

    // 2. Parsing e Validação Estrutural Segura
    let parsedJson;
    try {
      parsedJson = JSON.parse(rawBody);
    } catch {
      return res.status(400).json({ error: 'Payload JSON malformado.' });
    }

    const parseResult = webhookPayloadSchema.safeParse(parsedJson);
    if (!parseResult.success) {
      console.warn('[Validation] Payload do webhook inválido:', parseResult.error.flatten());
      return res.status(422).json({ error: 'Estrutura do payload incompatível.' });
    }

    const { id: eventId, event, data } = parseResult.data;
    const { invoice_id, tenant_id } = data;

    // 3. Execução Transacional com Isolamento Multi-tenant e Idempotência
    const dbClient = await getDatabaseConnection();

    try {
      await dbClient.query('BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED;');

      // 3.1 Idempotência: Checa se o evento já foi processado anteriormente
      const existingEvent = await dbClient.query(
        'SELECT id FROM processed_webhook_events WHERE event_id = $1 FOR UPDATE;',
        [eventId]
      );

      if (existingEvent.rows.length > 0) {
        await dbClient.query('ROLLBACK;');
        // Retorna 200 para sinalizar ao gateway que o evento já foi aceito
        return res.status(200).json({ status: 'ignored_duplicate' });
      }

      // 3.2 Isolamento de Tenant (OWASP A01): Filtra ESTRITAMENTE por ID e TENANT_ID
      const invoiceResult = await dbClient.query(
        `SELECT id, status, amount
         FROM invoices
         WHERE id = $1 AND tenant_id = $2
         FOR UPDATE;`,
        [invoice_id, tenant_id]
      );

      if (invoiceResult.rows.length === 0) {
        await dbClient.query('ROLLBACK;');
        console.error(`[Inconsistency] Fatura ${invoice_id} não encontrada para o Tenant ${tenant_id}.`);
        return res.status(404).json({ error: 'Fatura ou locatário não localizado.' });
      }

      const invoice = invoiceResult.rows[0];

      // 3.3 Mapeamento de Estado e Atualização
      let newStatus;
      if (event === 'invoice.paid') {
        newStatus = 'PAID';
      } else if (event === 'invoice.payment_failed') {
        newStatus = 'FAILED';
      }

      // Apenas transiciona se a fatura ainda estiver pendente
      if (invoice.status === 'PENDING') {
        await dbClient.query(
          `UPDATE invoices
           SET status = $1,
               paid_at = CASE WHEN $1 = 'PAID' THEN NOW() ELSE NULL END,
               updated_at = NOW()
           WHERE id = $2 AND tenant_id = $3;`,
          [newStatus, invoice_id, tenant_id]
        );
      }

      // 3.4 Registra o log do evento processado para garantia de idempotência
      await dbClient.query(
        `INSERT INTO processed_webhook_events (event_id, tenant_id, invoice_id, event_type, created_at)
         VALUES ($1, $2, $3, $4, NOW());`,
        [eventId, tenant_id, invoice_id, event]
      );

      await dbClient.query('COMMIT;');

      return res.status(200).json({ status: 'processed' });
    } catch (error) {
      await dbClient.query('ROLLBACK;');
      // OWASP A09: Security Logging & Failures - log interno detalhado, resposta opaca
      console.error('[Error] Falha ao processar webhook de faturamento:', error);
      return res.status(500).json({ error: 'Erro interno ao processar notificação.' });
    } finally {
      dbClient.release();
    }
  }
);

export default router;