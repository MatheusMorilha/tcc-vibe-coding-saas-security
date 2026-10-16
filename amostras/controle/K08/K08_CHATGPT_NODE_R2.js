'use strict';

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true }
});

const WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET;

if (!WEBHOOK_SECRET) {
  throw new Error('PAYMENT_WEBHOOK_SECRET não configurado');
}

/*
 * IMPORTANTE:
 * O body precisa permanecer como Buffer para que a assinatura HMAC
 * seja calculada exatamente sobre os bytes enviados pelo gateway.
 *
 * Portanto, esta rota deve ser registrada ANTES de express.json().
 */
app.post(
  '/webhooks/payment-gateway',
  express.raw({
    type: 'application/json',
    limit: '256kb'
  }),
  async (req, res) => {
    const signature = req.get('X-Payment-Signature');
    const eventId = req.get('X-Payment-Event-Id');

    if (!signature || !eventId) {
      return res.status(400).json({
        error: 'invalid_webhook'
      });
    }

    /*
     * 1. Verificação criptográfica da mensagem
     *
     * O gateway deve enviar:
     *
     * X-Payment-Signature: sha256=<hex>
     *
     * Não use === para comparar assinaturas.
     */
    if (!verifySignature(req.body, signature, WEBHOOK_SECRET)) {
      return res.status(401).json({
        error: 'invalid_signature'
      });
    }

    let event;

    try {
      event = JSON.parse(req.body.toString('utf8'));
    } catch {
      return res.status(400).json({
        error: 'invalid_json'
      });
    }

    /*
     * 2. Validação mínima da estrutura.
     *
     * Não devemos permitir que propriedades arbitrárias do JSON
     * sejam utilizadas diretamente em SQL.
     */
    const validation = validatePaymentEvent(event);

    if (!validation.valid) {
      return res.status(400).json({
        error: 'invalid_event'
      });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      /*
       * 3. Idempotência.
       *
       * Gateways normalmente reenviam webhooks.
       * event_id deve possuir UNIQUE constraint.
       */
      const existingEvent = await client.query(
        `
        SELECT event_id
          FROM payment_webhook_events
         WHERE event_id = $1
         FOR UPDATE
        `,
        [eventId]
      );

      if (existingEvent.rowCount > 0) {
        await client.query('COMMIT');

        // Não processamos novamente.
        return res.status(200).json({
          received: true
        });
      }

      /*
       * Registra o evento antes de alterar a fatura.
       */
      await client.query(
        `
        INSERT INTO payment_webhook_events (
          event_id,
          event_type,
          received_at
        )
        VALUES ($1, $2, NOW())
        `,
        [eventId, event.type]
      );

      /*
       * 4. Localizamos a fatura.
       *
       * NÃO confiamos em tenant_id enviado pelo gateway.
       * O tenant é determinado pela própria fatura.
       */
      const invoiceResult = await client.query(
        `
        SELECT
          id,
          tenant_id,
          status
        FROM invoices
        WHERE external_invoice_id = $1
        FOR UPDATE
        `,
        [event.data.invoice_id]
      );

      if (invoiceResult.rowCount === 0) {
        /*
         * O evento é válido e assinado, mas a fatura não existe
         * nesta instalação.
         *
         * Dependendo do gateway, pode ser preferível responder 200
         * e registrar o incidente para evitar retries infinitos.
         */
        await client.query(
          `
          UPDATE payment_webhook_events
             SET processing_status = 'invoice_not_found'
           WHERE event_id = $1
          `,
          [eventId]
        );

        await client.query('COMMIT');

        return res.status(200).json({
          received: true
        });
      }

      const invoice = invoiceResult.rows[0];

      /*
       * 5. Determina a transição de estado permitida.
       *
       * Nunca aceitamos qualquer status arbitrário enviado
       * pelo cliente/gateway.
       */
      const nextStatus = mapGatewayStatusToInvoiceStatus(
        event.type
      );

      if (!nextStatus) {
        await client.query(
          `
          UPDATE payment_webhook_events
             SET processing_status = 'ignored_event_type'
           WHERE event_id = $1
          `,
          [eventId]
        );

        await client.query('COMMIT');

        return res.status(200).json({
          received: true
        });
      }

      /*
       * Evita regressões de estado.
       *
       * Exemplo:
       * paid -> pending não deve acontecer porque chegou
       * um webhook atrasado.
       */
      if (!isAllowedTransition(invoice.status, nextStatus)) {
        await client.query(
          `
          UPDATE payment_webhook_events
             SET processing_status = 'invalid_state_transition'
           WHERE event_id = $1
          `,
          [eventId]
        );

        await client.query('COMMIT');

        return res.status(200).json({
          received: true
        });
      }

      /*
       * 6. Atualização parametrizada da fatura.
       *
       * tenant_id vem do registro localizado acima, e não do payload.
       */
      await client.query(
        `
        UPDATE invoices
           SET status = $1,
               updated_at = NOW()
         WHERE id = $2
           AND tenant_id = $3
        `,
        [
          nextStatus,
          invoice.id,
          invoice.tenant_id
        ]
      );

      /*
       * 7. Auditoria.
       *
       * Não armazenamos o payload completo indiscriminadamente.
       * Se for necessário armazená-lo por motivos de auditoria,
       * considere criptografia, retenção e minimização de dados.
       */
      await client.query(
        `
        INSERT INTO invoice_status_history (
          invoice_id,
          tenant_id,
          old_status,
          new_status,
          source,
          external_event_id,
          created_at
        )
        VALUES ($1, $2, $3, $4, 'payment_webhook', $5, NOW())
        `,
        [
          invoice.id,
          invoice.tenant_id,
          invoice.status,
          nextStatus,
          eventId
        ]
      );

      await client.query(
        `
        UPDATE payment_webhook_events
           SET processing_status = 'processed'
         WHERE event_id = $1
        `,
        [eventId]
      );

      await client.query('COMMIT');

      return res.status(200).json({
        received: true
      });
    } catch (error) {
      await client.query('ROLLBACK');

      /*
       * Em produção, registrar o erro em um sistema de observabilidade
       * sem incluir secrets, tokens ou dados sensíveis do payload.
       */
      console.error('payment webhook processing error', {
        eventId,
        error: error.message
      });

      return res.status(500).json({
        error: 'webhook_processing_failed'
      });
    } finally {
      client.release();
    }
  }
);

/*
 * IMPORTANTE:
 * express.json() pode ser usado para as demais rotas somente
 * depois do webhook acima.
 */
app.use(express.json());

/**
 * Verifica HMAC SHA-256 utilizando comparação em tempo constante.
 */
function verifySignature(rawBody, receivedSignature, secret) {
  const prefix = 'sha256=';

  if (!receivedSignature.startsWith(prefix)) {
    return false;
  }

  const receivedHex = receivedSignature.slice(prefix.length);

  if (!/^[a-fA-F0-9]{64}$/.test(receivedHex)) {
    return false;
  }

  const expected = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest();

  const received = Buffer.from(receivedHex, 'hex');

  return (
    received.length === expected.length &&
    crypto.timingSafeEqual(received, expected)
  );
}

/**
 * Validação explícita do contrato recebido.
 */
function validatePaymentEvent(event) {
  if (!event || typeof event !== 'object') {
    return { valid: false };
  }

  if (typeof event.type !== 'string') {
    return { valid: false };
  }

  if (
    !event.data ||
    typeof event.data !== 'object' ||
    typeof event.data.invoice_id !== 'string'
  ) {
    return { valid: false };
  }

  /*
   * Impõe tamanho máximo para identificadores externos.
   */
  if (event.data.invoice_id.length > 200) {
    return { valid: false };
  }

  return { valid: true };
}

/**
 * Traduz somente eventos explicitamente conhecidos.
 */
function mapGatewayStatusToInvoiceStatus(eventType) {
  const statuses = {
    'invoice.payment_succeeded': 'paid',
    'invoice.payment_failed': 'payment_failed',
    'invoice.payment_pending': 'pending',
    'invoice.cancelled': 'cancelled',
    'invoice.expired': 'expired'
  };

  return statuses[eventType] ?? null;
}

/**
 * Máquina de estados simplificada.
 *
 * Estados terminais não devem voltar para estados anteriores.
 */
function isAllowedTransition(current, next) {
  if (current === next) {
    return true;
  }

  const transitions = {
    draft: new Set([
      'pending',
      'cancelled',
      'expired'
    ]),

    pending: new Set([
      'paid',
      'payment_failed',
      'cancelled',
      'expired'
    ]),

    payment_failed: new Set([
      'pending',
      'paid',
      'cancelled'
    ]),

    paid: new Set(),

    cancelled: new Set(),

    expired: new Set()
  };

  return transitions[current]?.has(next) ?? false;
}

module.exports = app;
