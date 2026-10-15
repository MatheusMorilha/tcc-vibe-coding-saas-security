'use strict';

/**
 * Webhook do gateway de pagamento - SaaS multilocatário
 *
 * Garantias:
 *  1. Autenticidade: assinatura HMAC-SHA256 sobre o corpo BRUTO + timestamp (anti-replay).
 *  2. Isolamento de tenant: o tenant NUNCA vem do payload; é derivado da fatura
 *     localizada pelo ID do gateway. Toda escrita derivada usa esse tenant_id.
 *  3. Idempotência: tabela de eventos com UNIQUE (provider, event_id).
 *  4. Consistência: tudo em uma única transação, com lock de linha (FOR UPDATE).
 *  5. Máquina de estados: transições inválidas/fora de ordem são ignoradas.
 *  6. Integridade financeira: valor e moeda do evento são conferidos com a fatura.
 *
 * DDL de apoio (PostgreSQL):
 *
 *   CREATE TABLE invoices (
 *     id                  BIGSERIAL PRIMARY KEY,
 *     tenant_id           BIGINT NOT NULL REFERENCES tenants(id),
 *     gateway_invoice_id  TEXT   NOT NULL UNIQUE,
 *     amount_cents        BIGINT NOT NULL,
 *     currency            CHAR(3) NOT NULL,
 *     status              TEXT   NOT NULL DEFAULT 'open',
 *     paid_at             TIMESTAMPTZ,
 *     updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *
 *   CREATE TABLE webhook_events (
 *     id           BIGSERIAL PRIMARY KEY,
 *     provider     TEXT NOT NULL,
 *     event_id     TEXT NOT NULL,
 *     event_type   TEXT NOT NULL,
 *     tenant_id    BIGINT,
 *     invoice_id   BIGINT,
 *     outcome      TEXT NOT NULL,   -- applied | ignored | unmatched | mismatch
 *     received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
 *     UNIQUE (provider, event_id)
 *   );
 */

const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');

const PROVIDER = 'gateway';
const SIGNATURE_TOLERANCE_SECONDS = 300; // 5 min
const WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET;

if (!WEBHOOK_SECRET) {
  throw new Error('PAYMENT_WEBHOOK_SECRET não configurado');
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

/* ------------------------------------------------------------------ */
/* Máquina de estados da fatura                                        */
/* ------------------------------------------------------------------ */

const EVENT_TO_STATUS = {
  'invoice.paid': 'paid',
  'invoice.payment_failed': 'failed',
  'invoice.canceled': 'canceled',
  'invoice.refunded': 'refunded',
};

const ALLOWED_TRANSITIONS = {
  open: new Set(['paid', 'failed', 'canceled']),
  failed: new Set(['paid', 'canceled']),
  paid: new Set(['refunded']),
  canceled: new Set(),
  refunded: new Set(),
};

/* ------------------------------------------------------------------ */
/* Verificação de assinatura                                           */
/* Header esperado: X-Gateway-Signature: t=<unix>,v1=<hex>             */
/* ------------------------------------------------------------------ */

function verifySignature(rawBody, header) {
  if (typeof header !== 'string') return false;

  const parts = Object.fromEntries(
    header.split(',').map((p) => {
      const i = p.indexOf('=');
      return [p.slice(0, i).trim(), p.slice(i + 1).trim()];
    })
  );

  const timestamp = Number(parts.t);
  const received = parts.v1;
  if (!Number.isInteger(timestamp) || !received || !/^[0-9a-f]{64}$/i.test(received)) {
    return false;
  }

  // Anti-replay
  const age = Math.abs(Math.floor(Date.now() / 1000) - timestamp);
  if (age > SIGNATURE_TOLERANCE_SECONDS) return false;

  const expected = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(`${timestamp}.`)
    .update(rawBody)
    .digest();

  const receivedBuf = Buffer.from(received, 'hex');
  return (
    receivedBuf.length === expected.length &&
    crypto.timingSafeEqual(receivedBuf, expected)
  );
}

/* ------------------------------------------------------------------ */
/* Validação do payload                                                */
/* ------------------------------------------------------------------ */

function parseEvent(rawBody) {
  let body;
  try {
    body = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return null;
  }

  const d = body && body.data;
  if (
    !body ||
    typeof body.id !== 'string' || !body.id || body.id.length > 128 ||
    typeof body.type !== 'string' || body.type.length > 64 ||
    !d ||
    typeof d.invoice_id !== 'string' || !d.invoice_id || d.invoice_id.length > 128 ||
    !Number.isSafeInteger(d.amount) || d.amount < 0 ||
    typeof d.currency !== 'string' || !/^[A-Za-z]{3}$/.test(d.currency)
  ) {
    return null;
  }

  return {
    eventId: body.id,
    type: body.type,
    gatewayInvoiceId: d.invoice_id,
    amountCents: d.amount,
    currency: d.currency.toUpperCase(),
  };
}

/* ------------------------------------------------------------------ */
/* Processamento (transacional)                                        */
/* ------------------------------------------------------------------ */

async function processEvent(evt) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1) Idempotência: se o evento já foi registrado, não faz nada.
    const ins = await client.query(
      `INSERT INTO webhook_events (provider, event_id, event_type, outcome)
       VALUES ($1, $2, $3, 'received')
       ON CONFLICT (provider, event_id) DO NOTHING
       RETURNING id`,
      [PROVIDER, evt.eventId, evt.type]
    );
    if (ins.rowCount === 0) {
      await client.query('ROLLBACK');
      return 'duplicate';
    }
    const eventRowId = ins.rows[0].id;

    const finish = async (outcome, invoice) => {
      await client.query(
        `UPDATE webhook_events
            SET outcome = $1, tenant_id = $2, invoice_id = $3
          WHERE id = $4`,
        [outcome, invoice ? invoice.tenant_id : null, invoice ? invoice.id : null, eventRowId]
      );
      await client.query('COMMIT');
      return outcome;
    };

    // 2) Tipo de evento desconhecido: confirma e segue (evita retry infinito).
    const newStatus = EVENT_TO_STATUS[evt.type];
    if (!newStatus) return await finish('ignored', null);

    // 3) Localiza a fatura pelo ID do gateway e trava a linha.
    //    O tenant é derivado daqui, nunca do payload.
    const { rows } = await client.query(
      `SELECT id, tenant_id, status, amount_cents, currency
         FROM invoices
        WHERE gateway_invoice_id = $1
        FOR UPDATE`,
      [evt.gatewayInvoiceId]
    );
    if (rows.length === 0) return await finish('unmatched', null);
    const invoice = rows[0];

    // 4) Confere valor/moeda antes de reconhecer pagamento.
    if (
      newStatus === 'paid' &&
      (Number(invoice.amount_cents) !== evt.amountCents || invoice.currency.trim() !== evt.currency)
    ) {
      return await finish('mismatch', invoice); // não marca como paga; alerta/auditoria
    }

    // 5) Valida a transição de estado (ignora fora de ordem/repetidos).
    if (!ALLOWED_TRANSITIONS[invoice.status]?.has(newStatus)) {
      return await finish('ignored', invoice);
    }

    // 6) Atualiza a fatura, sempre escopada por tenant_id.
    await client.query(
      `UPDATE invoices
          SET status = $1,
              paid_at = CASE WHEN $1 = 'paid' THEN now() ELSE paid_at END,
              updated_at = now()
        WHERE id = $2 AND tenant_id = $3`,
      [newStatus, invoice.id, invoice.tenant_id]
    );

    // 7) Efeito colateral na assinatura do mesmo tenant.
    if (newStatus === 'paid') {
      await client.query(
        `UPDATE subscriptions
            SET status = 'active', updated_at = now()
          WHERE tenant_id = $1 AND status IN ('past_due', 'pending')`,
        [invoice.tenant_id]
      );
    } else if (newStatus === 'failed') {
      await client.query(
        `UPDATE subscriptions
            SET status = 'past_due', updated_at = now()
          WHERE tenant_id = $1 AND status = 'active'`,
        [invoice.tenant_id]
      );
    }

    return await finish('applied', invoice);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err; // transação revertida => o gateway fará retry
  } finally {
    client.release();
  }
}

/* ------------------------------------------------------------------ */
/* Rota                                                                */
/* ------------------------------------------------------------------ */

const router = express.Router();

// IMPORTANTE: corpo bruto apenas nesta rota (a assinatura depende dos bytes originais).
// Não registre express.json() globalmente antes deste router.
router.post(
  '/webhooks/payments',
  express.raw({ type: 'application/json', limit: '256kb' }),
  async (req, res) => {
    const rawBody = req.body;

    if (!Buffer.isBuffer(rawBody) || rawBody.length === 0) {
      return res.status(400).json({ error: 'invalid_body' });
    }

    if (!verifySignature(rawBody, req.get('x-gateway-signature'))) {
      return res.status(401).json({ error: 'invalid_signature' });
    }

    const evt = parseEvent(rawBody);
    if (!evt) {
      return res.status(400).json({ error: 'invalid_payload' });
    }

    try {
      const outcome = await processEvent(evt);

      if (outcome === 'unmatched' || outcome === 'mismatch') {
        // Log sem PII/corpo completo; use para alertas e reconciliação.
        console.warn('[webhook] evento requer revisão', {
          outcome,
          eventId: evt.eventId,
          type: evt.type,
        });
      }

      // 2xx confirma o recebimento; o gateway não deve reenviar.
      return res.status(200).json({ received: true, outcome });
    } catch (err) {
      console.error('[webhook] falha ao processar', {
        eventId: evt.eventId,
        message: err.message,
      });
      return res.status(500).json({ error: 'internal_error' }); // dispara retry
    }
  }
);

module.exports = router;

/* Uso:
 *   const app = express();
 *   app.use(require('./paymentWebhook'));   // ANTES de app.use(express.json())
 *   app.use(express.json());
 */