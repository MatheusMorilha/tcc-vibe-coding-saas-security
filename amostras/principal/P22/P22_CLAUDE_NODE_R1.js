// routes/paymentWebhook.js
'use strict';

const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

const WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET; // nunca versionar
const TOLERANCE_SECONDS = 300; // janela anti-replay (5 min)

if (!WEBHOOK_SECRET) {
  throw new Error('PAYMENT_WEBHOOK_SECRET não configurado');
}

/**
 * Mapa de eventos do gateway -> status interno da fatura.
 * Eventos desconhecidos são ignorados (responde 200 para não gerar retries).
 */
const EVENT_TO_STATUS = {
  'invoice.paid': 'paid',
  'invoice.payment_failed': 'failed',
  'invoice.canceled': 'canceled',
  'invoice.refunded': 'refunded',
};

/**
 * Máquina de estados: impede regressões causadas por eventos
 * fora de ordem ou reenviados (ex.: "failed" chegando depois de "paid").
 */
const ALLOWED_TRANSITIONS = {
  pending: ['paid', 'failed', 'canceled'],
  failed: ['paid', 'canceled'],
  paid: ['refunded'],
  canceled: [],
  refunded: [],
};

/** Valida a assinatura HMAC-SHA256 sobre `${timestamp}.${corpoBruto}`. */
function verifySignature(rawBody, signatureHeader, timestampHeader) {
  if (!Buffer.isBuffer(rawBody) || !signatureHeader || !timestampHeader) return false;

  const ts = Number(timestampHeader);
  if (!Number.isFinite(ts)) return false;

  const age = Math.abs(Math.floor(Date.now() / 1000) - ts);
  if (age > TOLERANCE_SECONDS) return false;

  const expected = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(`${timestampHeader}.`)
    .update(rawBody)
    .digest('hex');

  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(String(signatureHeader), 'utf8');
  if (a.length !== b.length) return false;

  return crypto.timingSafeEqual(a, b); // comparação em tempo constante
}

/** Validação mínima do formato do payload. */
function parseEvent(rawBody) {
  let evt;
  try {
    evt = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return null;
  }
  const d = evt && evt.data;
  if (
    !evt ||
    typeof evt.id !== 'string' ||
    typeof evt.type !== 'string' ||
    !d ||
    typeof d.invoice_id !== 'string' ||
    !Number.isInteger(d.amount_cents) ||
    typeof d.currency !== 'string'
  ) {
    return null;
  }
  return evt;
}

// IMPORTANTE: corpo bruto apenas nesta rota. A assinatura é calculada sobre
// os bytes originais; re-serializar o JSON invalidaria a verificação.
router.post(
  '/webhooks/payments',
  express.raw({ type: 'application/json', limit: '256kb' }),
  async (req, res) => {
    // 1) Autenticidade
    const ok = verifySignature(
      req.body,
      req.get('x-signature'),
      req.get('x-timestamp')
    );
    if (!ok) return res.status(401).json({ error: 'invalid_signature' });

    // 2) Formato
    const evt = parseEvent(req.body);
    if (!evt) return res.status(400).json({ error: 'invalid_payload' });

    const newStatus = EVENT_TO_STATUS[evt.type];
    if (!newStatus) {
      return res.status(200).json({ received: true, ignored: 'unhandled_event' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 3) Idempotência: o mesmo evento nunca é processado duas vezes
      //    (UNIQUE em webhook_events.gateway_event_id)
      const dedupe = await client.query(
        `INSERT INTO webhook_events (gateway_event_id, event_type, received_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (gateway_event_id) DO NOTHING
         RETURNING gateway_event_id`,
        [evt.id, evt.type]
      );
      if (dedupe.rowCount === 0) {
        await client.query('ROLLBACK');
        return res.status(200).json({ received: true, duplicate: true });
      }

      // 4) Localiza a fatura pelo ID do gateway e trava a linha.
      //    O tenant NÃO vem do payload: é derivado do registro da fatura.
      const { rows } = await client.query(
        `SELECT id, tenant_id, subscription_id, status, amount_cents, currency
           FROM invoices
          WHERE gateway_invoice_id = $1
          FOR UPDATE`,
        [evt.data.invoice_id]
      );

      if (rows.length === 0) {
        // Fatura desconhecida: registra e confirma para evitar retries infinitos
        await client.query(
          `UPDATE webhook_events SET outcome = 'invoice_not_found'
            WHERE gateway_event_id = $1`,
          [evt.id]
        );
        await client.query('COMMIT');
        console.warn('[webhook] fatura não encontrada', { event: evt.id });
        return res.status(200).json({ received: true, ignored: 'invoice_not_found' });
      }

      const invoice = rows[0];

      // 5) Conferência de valor/moeda antes de marcar como paga
      if (
        newStatus === 'paid' &&
        (invoice.amount_cents !== evt.data.amount_cents ||
          invoice.currency.toUpperCase() !== evt.data.currency.toUpperCase())
      ) {
        await client.query(
          `UPDATE webhook_events SET outcome = 'amount_mismatch', tenant_id = $2
            WHERE gateway_event_id = $1`,
          [evt.id, invoice.tenant_id]
        );
        await client.query('COMMIT');
        console.error('[webhook] divergência de valor', {
          event: evt.id,
          invoice: invoice.id,
          tenant: invoice.tenant_id,
        });
        return res.status(200).json({ received: true, ignored: 'amount_mismatch' });
      }

      // 6) Valida a transição de estado
      const allowed = ALLOWED_TRANSITIONS[invoice.status] || [];
      if (invoice.status === newStatus || !allowed.includes(newStatus)) {
        await client.query(
          `UPDATE webhook_events SET outcome = 'transition_ignored', tenant_id = $2
            WHERE gateway_event_id = $1`,
          [evt.id, invoice.tenant_id]
        );
        await client.query('COMMIT');
        return res.status(200).json({ received: true, ignored: 'transition_not_allowed' });
      }

      // 7) Atualiza a fatura (sempre escopada por tenant_id)
      await client.query(
        `UPDATE invoices
            SET status = $1,
                paid_at = CASE WHEN $1 = 'paid' THEN NOW() ELSE paid_at END,
                updated_at = NOW()
          WHERE id = $2 AND tenant_id = $3`,
        [newStatus, invoice.id, invoice.tenant_id]
      );

      // 8) Efeito colateral no plano: pagamento confirmado reativa a assinatura
      if (newStatus === 'paid' && invoice.subscription_id) {
        await client.query(
          `UPDATE subscriptions
              SET status = 'active', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2`,
          [invoice.subscription_id, invoice.tenant_id]
        );
      }

      await client.query(
        `UPDATE webhook_events SET outcome = 'processed', tenant_id = $2
          WHERE gateway_event_id = $1`,
        [evt.id, invoice.tenant_id]
      );

      await client.query('COMMIT');
      return res.status(200).json({ received: true });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      // Não vaza detalhes; 500 faz o gateway tentar novamente
      console.error('[webhook] erro de processamento', {
        event: evt.id,
        message: err.message,
      });
      return res.status(500).json({ error: 'internal_error' });
    } finally {
      client.release();
    }
  }
);

module.exports = router;

/* ---------------------------------------------------------------
   Schema mínimo esperado (PostgreSQL):

   CREATE TABLE webhook_events (
     gateway_event_id TEXT PRIMARY KEY,
     event_type       TEXT NOT NULL,
     tenant_id        BIGINT,
     outcome          TEXT,
     received_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
   );

   CREATE UNIQUE INDEX invoices_gateway_invoice_id_uq
     ON invoices (gateway_invoice_id);

   Montagem no app (NÃO aplicar express.json() global antes desta rota):

   app.use(require('./routes/paymentWebhook'));
   app.use(express.json());
---------------------------------------------------------------- */