'use strict';

/**
 * POST /webhooks/payments
 *
 * Recebe notificações do gateway de pagamento e atualiza o estado da fatura.
 *
 * Esquema de banco assumido (PostgreSQL):
 *
 *   CREATE TABLE invoices (
 *     id                  BIGSERIAL PRIMARY KEY,
 *     tenant_id           BIGINT      NOT NULL,
 *     gateway_invoice_id  TEXT        NOT NULL UNIQUE,   -- id da cobrança no gateway
 *     amount_cents        BIGINT      NOT NULL,
 *     currency            CHAR(3)     NOT NULL,
 *     status              TEXT        NOT NULL DEFAULT 'open',
 *     paid_at             TIMESTAMPTZ,
 *     updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *
 *   CREATE TABLE webhook_events (                        -- idempotência + auditoria
 *     gateway     TEXT        NOT NULL,
 *     event_id    TEXT        NOT NULL,
 *     tenant_id   BIGINT,
 *     invoice_id  BIGINT,
 *     event_type  TEXT        NOT NULL,
 *     received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 *     PRIMARY KEY (gateway, event_id)
 *   );
 *
 * Variáveis de ambiente:
 *   PAYMENT_WEBHOOK_SECRETS  -> um ou mais segredos separados por vírgula (permite rotação)
 *   DATABASE_URL
 */

const crypto = require('node:crypto');
const express = require('express');
const { Pool } = require('pg');

const GATEWAY = 'meu-gateway';
const TOLERANCE_SECONDS = 5 * 60; // janela anti-replay
const MAX_BODY = '256kb';

const SECRETS = (process.env.PAYMENT_WEBHOOK_SECRETS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

if (SECRETS.length === 0) {
  // Falha na subida: nunca operar sem segredo configurado.
  throw new Error('PAYMENT_WEBHOOK_SECRETS não configurado');
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

/* ------------------------------------------------------------------ */
/* Mapeamento de eventos e máquina de estados                          */
/* ------------------------------------------------------------------ */

// Evento do gateway -> status interno da fatura
const EVENT_TO_STATUS = {
  'payment.pending': 'pending',
  'payment.succeeded': 'paid',
  'invoice.paid': 'paid',
  'payment.failed': 'failed',
  'invoice.canceled': 'canceled',
  'payment.refunded': 'refunded',
};

// Transições permitidas. Protege contra eventos fora de ordem
// (ex.: "pending" chegando depois de "paid").
const ALLOWED_TRANSITIONS = {
  open: ['pending', 'paid', 'failed', 'canceled'],
  pending: ['paid', 'failed', 'canceled'],
  failed: ['pending', 'paid', 'canceled'],
  paid: ['refunded'],
  canceled: [],
  refunded: [],
};

/* ------------------------------------------------------------------ */
/* Verificação de assinatura                                           */
/* ------------------------------------------------------------------ */

function verifySignature(rawBody, signatureHeader, timestampHeader) {
  if (!Buffer.isBuffer(rawBody) || !signatureHeader || !timestampHeader) return false;

  const ts = Number(timestampHeader);
  if (!Number.isInteger(ts)) return false;

  const age = Math.abs(Math.floor(Date.now() / 1000) - ts);
  if (age > TOLERANCE_SECONDS) return false; // replay ou relógio dessincronizado

  const received = Buffer.from(String(signatureHeader), 'hex');
  const signedPayload = Buffer.concat([Buffer.from(`${ts}.`), rawBody]);

  return SECRETS.some((secret) => {
    const expected = crypto.createHmac('sha256', secret).update(signedPayload).digest();
    // timingSafeEqual exige buffers de mesmo tamanho
    return received.length === expected.length && crypto.timingSafeEqual(received, expected);
  });
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

  const eventId = body?.id;
  const type = body?.type;
  const invoiceRef = body?.data?.invoice_id;
  const amount = body?.data?.amount_cents;
  const currency = body?.data?.currency;

  const valid =
    typeof eventId === 'string' && eventId.length > 0 && eventId.length <= 128 &&
    typeof type === 'string' &&
    typeof invoiceRef === 'string' && invoiceRef.length > 0 && invoiceRef.length <= 128 &&
    Number.isSafeInteger(amount) && amount >= 0 &&
    typeof currency === 'string' && /^[A-Za-z]{3}$/.test(currency);

  return valid
    ? { eventId, type, invoiceRef, amount, currency: currency.toUpperCase() }
    : null;
}

/* ------------------------------------------------------------------ */
/* Processamento transacional                                          */
/* ------------------------------------------------------------------ */

async function processEvent(evt) {
  const newStatus = EVENT_TO_STATUS[evt.type];
  if (!newStatus) return { outcome: 'ignored_type' };

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1) Idempotência: o gateway reenvia eventos; processar só uma vez.
    const dedupe = await client.query(
      `INSERT INTO webhook_events (gateway, event_id, event_type)
       VALUES ($1, $2, $3)
       ON CONFLICT (gateway, event_id) DO NOTHING`,
      [GATEWAY, evt.eventId, evt.type]
    );
    if (dedupe.rowCount === 0) {
      await client.query('ROLLBACK');
      return { outcome: 'duplicate' };
    }

    // 2) O tenant é DERIVADO da fatura (identificador do gateway), nunca do payload.
    //    FOR UPDATE serializa eventos concorrentes da mesma fatura.
    const { rows } = await client.query(
      `SELECT id, tenant_id, status, amount_cents, currency
         FROM invoices
        WHERE gateway_invoice_id = $1
        FOR UPDATE`,
      [evt.invoiceRef]
    );

    if (rows.length === 0) {
      // Desfaz também o registro de idempotência: se o gateway reenviar
      // depois (ex.: fatura ainda sendo criada), o evento poderá ser processado.
      await client.query('ROLLBACK');
      return { outcome: 'invoice_not_found' };
    }

    const invoice = rows[0];

    // 3) Confere valor e moeda contra o que foi cobrado.
    if (Number(invoice.amount_cents) !== evt.amount || invoice.currency.trim() !== evt.currency) {
      await client.query('ROLLBACK');
      return { outcome: 'amount_mismatch', tenantId: invoice.tenant_id, invoiceId: invoice.id };
    }

    // 4) Valida a transição de estado.
    const allowed = ALLOWED_TRANSITIONS[invoice.status] || [];
    if (invoice.status !== newStatus && !allowed.includes(newStatus)) {
      // Evento válido, porém obsoleto/fora de ordem: registra e ignora.
      await client.query(
        `UPDATE webhook_events SET tenant_id = $3, invoice_id = $4
          WHERE gateway = $1 AND event_id = $2`,
        [GATEWAY, evt.eventId, invoice.tenant_id, invoice.id]
      );
      await client.query('COMMIT');
      return { outcome: 'invalid_transition', tenantId: invoice.tenant_id, invoiceId: invoice.id };
    }

    // 5) Atualiza a fatura. tenant_id no WHERE como defesa em profundidade.
    await client.query(
      `UPDATE invoices
          SET status     = $1,
              paid_at    = CASE WHEN $1 = 'paid' THEN now() ELSE paid_at END,
              updated_at = now()
        WHERE id = $2 AND tenant_id = $3`,
      [newStatus, invoice.id, invoice.tenant_id]
    );

    await client.query(
      `UPDATE webhook_events SET tenant_id = $3, invoice_id = $4
        WHERE gateway = $1 AND event_id = $2`,
      [GATEWAY, evt.eventId, invoice.tenant_id, invoice.id]
    );

    await client.query('COMMIT');
    return { outcome: 'updated', tenantId: invoice.tenant_id, invoiceId: invoice.id, newStatus };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/* ------------------------------------------------------------------ */
/* Rota                                                                */
/* ------------------------------------------------------------------ */

const router = express.Router();

// express.raw é aplicado SOMENTE nesta rota: a assinatura é calculada sobre
// os bytes originais; um express.json() antes dela invalidaria a verificação.
router.post(
  '/webhooks/payments',
  express.raw({ type: 'application/json', limit: MAX_BODY }),
  async (req, res) => {
    const signature = req.get('x-gateway-signature');
    const timestamp = req.get('x-gateway-timestamp');

    // 1) Autenticidade primeiro. Nada do corpo é interpretado antes disso.
    if (!verifySignature(req.body, signature, timestamp)) {
      return res.status(401).json({ error: 'invalid_signature' });
    }

    // 2) Estrutura do payload.
    const evt = parseEvent(req.body);
    if (!evt) {
      return res.status(400).json({ error: 'invalid_payload' });
    }

    // 3) Processamento.
    try {
      const result = await processEvent(evt);

      // Log estruturado sem dados sensíveis (sem corpo, sem assinatura).
      console.info(
        JSON.stringify({
          msg: 'payment_webhook',
          gateway: GATEWAY,
          eventId: evt.eventId,
          type: evt.type,
          ...result,
        })
      );

      switch (result.outcome) {
        case 'invoice_not_found':
          // 404 faz o gateway reenviar com backoff; útil se houver corrida
          // entre criação da fatura e o webhook.
          return res.status(404).json({ error: 'invoice_not_found' });
        case 'amount_mismatch':
          // Não é retentável: responde 422 e deve gerar alerta operacional.
          console.error(
            JSON.stringify({ msg: 'payment_webhook_amount_mismatch', eventId: evt.eventId, ...result })
          );
          return res.status(422).json({ error: 'amount_mismatch' });
        default:
          // updated | duplicate | ignored_type | invalid_transition
          return res.status(200).json({ received: true });
      }
    } catch (err) {
      console.error(
        JSON.stringify({ msg: 'payment_webhook_error', eventId: evt.eventId, error: err.message })
      );
      // 500 -> o gateway tenta novamente; a idempotência garante segurança no reenvio.
      return res.status(500).json({ error: 'internal_error' });
    }
  }
);

module.exports = router;

/* Uso no app principal:
 *
 *   const app = express();
 *   app.use(require('./paymentWebhook'));   // ANTES de qualquer express.json() global
 *   app.use(express.json());
 */