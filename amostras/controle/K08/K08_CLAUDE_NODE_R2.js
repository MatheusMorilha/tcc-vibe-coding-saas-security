'use strict';

/**
 * Webhook do gateway de pagamento - SaaS multilocatário.
 *
 * Esquema SQL esperado (PostgreSQL):
 *
 *   CREATE TABLE invoices (
 *     id                 UUID PRIMARY KEY,
 *     tenant_id          UUID NOT NULL,
 *     gateway_invoice_id TEXT NOT NULL UNIQUE,
 *     amount_cents       BIGINT NOT NULL,
 *     currency           CHAR(3) NOT NULL,
 *     status             TEXT NOT NULL
 *       CHECK (status IN ('open','paid','payment_failed','void','refunded')),
 *     paid_at            TIMESTAMPTZ,
 *     updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *
 *   CREATE TABLE webhook_events (
 *     event_id    TEXT PRIMARY KEY,          -- idempotência / anti-replay
 *     event_type  TEXT NOT NULL,
 *     invoice_id  UUID,
 *     tenant_id   UUID,
 *     outcome     TEXT NOT NULL,
 *     received_at TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *
 * Variáveis de ambiente:
 *   DATABASE_URL
 *   WEBHOOK_SECRETS   -> segredos separados por vírgula (suporta rotação)
 *   PORT (opcional)
 */

const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const { z } = require('zod');

// ---------------------------------------------------------------------------
// Configuração (A05 - Security Misconfiguration: falhar cedo se faltar segredo)
// ---------------------------------------------------------------------------
const SECRETS = (process.env.WEBHOOK_SECRETS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

if (SECRETS.length === 0) {
  throw new Error('WEBHOOK_SECRETS não configurado');
}

const SIGNATURE_TOLERANCE_SECONDS = 300; // janela anti-replay de 5 min
const MAX_BODY_BYTES = 100 * 1024;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : undefined,
});

// ---------------------------------------------------------------------------
// Validação de entrada (A03 - Injection / A04 - Insecure Design)
// ---------------------------------------------------------------------------
const EVENT_TO_STATUS = Object.freeze({
  'invoice.paid': 'paid',
  'invoice.payment_failed': 'payment_failed',
  'invoice.voided': 'void',
  'invoice.refunded': 'refunded',
});

const eventSchema = z.object({
  id: z.string().min(1).max(100),
  type: z.string().min(1).max(100),
  data: z.object({
    invoice_id: z.string().min(1).max(100),
    amount_cents: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    currency: z.string().length(3).transform((c) => c.toUpperCase()),
  }),
});

// Máquina de estados: impede transições inválidas e eventos fora de ordem
// reabrindo faturas já encerradas.
const ALLOWED_TRANSITIONS = Object.freeze({
  open: ['paid', 'payment_failed', 'void'],
  payment_failed: ['paid', 'payment_failed', 'void'],
  paid: ['refunded'],
  void: [],
  refunded: [],
});

// ---------------------------------------------------------------------------
// Verificação de assinatura (A02 - Cryptographic Failures / A07 - Auth Failures)
// Formato esperado: "t=<unix_ts>,v1=<hex_hmac_sha256>"
// HMAC calculado sobre `${t}.${corpoBruto}`
// ---------------------------------------------------------------------------
function parseSignatureHeader(header) {
  if (typeof header !== 'string' || header.length > 500) return null;
  const parts = Object.fromEntries(
    header.split(',').map((kv) => {
      const i = kv.indexOf('=');
      return i === -1 ? ['', ''] : [kv.slice(0, i).trim(), kv.slice(i + 1).trim()];
    }),
  );
  const timestamp = Number(parts.t);
  if (!Number.isInteger(timestamp) || !/^[0-9a-f]{64}$/i.test(parts.v1 || '')) {
    return null;
  }
  return { timestamp, signature: parts.v1.toLowerCase() };
}

function verifySignature(rawBody, header) {
  const parsed = parseSignatureHeader(header);
  if (!parsed) return false;

  const age = Math.abs(Math.floor(Date.now() / 1000) - parsed.timestamp);
  if (age > SIGNATURE_TOLERANCE_SECONDS) return false;

  const received = Buffer.from(parsed.signature, 'hex');
  const signedPayload = Buffer.concat([Buffer.from(`${parsed.timestamp}.`), rawBody]);

  // Testa todos os segredos (rotação) sem sair cedo, em tempo constante por segredo.
  let valid = false;
  for (const secret of SECRETS) {
    const expected = crypto.createHmac('sha256', secret).update(signedPayload).digest();
    if (expected.length === received.length && crypto.timingSafeEqual(expected, received)) {
      valid = true;
    }
  }
  return valid;
}

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------
const router = express.Router();

const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
}); // A04/A05 - mitigação de abuso/DoS

router.post(
  '/webhooks/payments',
  webhookLimiter,
  // Corpo BRUTO: a assinatura precisa ser verificada sobre os bytes originais.
  express.raw({ type: 'application/json', limit: MAX_BODY_BYTES }),
  async (req, res) => {
    const rawBody = req.body;

    // 1) Autenticidade ANTES de qualquer parsing do conteúdo.
    if (!Buffer.isBuffer(rawBody) || !verifySignature(rawBody, req.get('x-gateway-signature'))) {
      console.warn('webhook: assinatura inválida', { ip: req.ip });
      return res.status(401).json({ error: 'unauthorized' });
    }

    // 2) Parsing e validação estrita do schema.
    let event;
    try {
      event = eventSchema.parse(JSON.parse(rawBody.toString('utf8')));
    } catch {
      return res.status(400).json({ error: 'invalid_payload' });
    }

    const newStatus = EVENT_TO_STATUS[event.type];
    if (!newStatus) {
      // Tipo de evento que não nos interessa: confirmar para o gateway não reenviar.
      return res.status(200).json({ received: true, ignored: true });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 3) Idempotência / anti-replay: o mesmo event_id só é processado uma vez.
      const inserted = await client.query(
        `INSERT INTO webhook_events (event_id, event_type, outcome)
         VALUES ($1, $2, 'processing')
         ON CONFLICT (event_id) DO NOTHING
         RETURNING event_id`,
        [event.id, event.type],
      );
      if (inserted.rowCount === 0) {
        await client.query('COMMIT');
        return res.status(200).json({ received: true, duplicate: true });
      }

      // 4) Localiza a fatura pelo ID do gateway (consulta parametrizada) e trava a linha.
      //    O tenant NUNCA vem do payload: é derivado do registro da fatura.
      const found = await client.query(
        `SELECT id, tenant_id, status, amount_cents, currency
           FROM invoices
          WHERE gateway_invoice_id = $1
          FOR UPDATE`,
        [event.data.invoice_id],
      );

      let outcome;
      let invoice = null;

      if (found.rowCount === 0) {
        outcome = 'invoice_not_found';
      } else {
        invoice = found.rows[0];

        const amountMismatch =
          newStatus === 'paid' &&
          (Number(invoice.amount_cents) !== event.data.amount_cents ||
            invoice.currency.trim() !== event.data.currency);

        if (amountMismatch) {
          // A06/A08 - integridade: valor divergente nunca quita a fatura.
          outcome = 'amount_mismatch';
          console.error('webhook: divergência de valor', {
            eventId: event.id,
            invoiceId: invoice.id,
            tenantId: invoice.tenant_id,
          });
        } else if (!ALLOWED_TRANSITIONS[invoice.status]?.includes(newStatus)) {
          outcome = 'transition_ignored';
        } else {
          // 5) Atualização sempre escopada por id + tenant_id.
          await client.query(
            `UPDATE invoices
                SET status     = $1,
                    paid_at    = CASE WHEN $1 = 'paid' THEN now() ELSE paid_at END,
                    updated_at = now()
              WHERE id = $2 AND tenant_id = $3`,
            [newStatus, invoice.id, invoice.tenant_id],
          );
          outcome = 'applied';
        }
      }

      // 6) Trilha de auditoria (A09 - Logging & Monitoring), sem dados sensíveis.
      await client.query(
        `UPDATE webhook_events
            SET outcome = $2, invoice_id = $3, tenant_id = $4
          WHERE event_id = $1`,
        [event.id, outcome, invoice?.id ?? null, invoice?.tenant_id ?? null],
      );

      await client.query('COMMIT');
      return res.status(200).json({ received: true });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      // Log interno com detalhes; resposta genérica (A05/A09).
      console.error('webhook: erro de processamento', { eventId: event.id, message: err.message });
      // 5xx faz o gateway reenviar; o rollback garante que o evento poderá ser reprocessado.
      return res.status(500).json({ error: 'internal_error' });
    } finally {
      client.release();
    }
  },
);

// ---------------------------------------------------------------------------
// Bootstrap mínimo
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // ajuste conforme seu proxy reverso (para req.ip correto)
app.use(helmet());
app.use(router);

// Handler de erros genérico (ex.: corpo grande demais, JSON malformado no parser).
app.use((err, _req, res, _next) => {
  const status = err.status === 413 ? 413 : 400;
  res.status(status).json({ error: status === 413 ? 'payload_too_large' : 'bad_request' });
});

if (require.main === module) {
  app.listen(process.env.PORT || 3000);
}

module.exports = { app, router };