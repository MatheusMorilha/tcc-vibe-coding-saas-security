'use strict';

/**
 * routes/paymentWebhook.js
 *
 * Recebe notificações do gateway de pagamento e atualiza o estado da fatura.
 *
 * Dependências: express, pg, zod, express-rate-limit
 * Variáveis de ambiente:
 *   PAYMENT_WEBHOOK_SECRETS  -> segredos separados por vírgula (permite rotação)
 *   DATABASE_URL
 */

const express = require('express');
const crypto = require('node:crypto');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const { Pool } = require('pg');

// ---------------------------------------------------------------------------
// Configuração (fail closed: sem segredo, a aplicação nem sobe)
// ---------------------------------------------------------------------------
const SECRETS = (process.env.PAYMENT_WEBHOOK_SECRETS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

if (SECRETS.length === 0) {
  throw new Error('PAYMENT_WEBHOOK_SECRETS não configurado');
}

const SIGNATURE_HEADER = 'x-gateway-signature'; // formato: t=1700000000,v1=<hex>
const TOLERANCE_SECONDS = 300; // janela anti-replay de 5 minutos
const MAX_BODY_BYTES = 100 * 1024;
const GATEWAY_NAME = 'gateway_x';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Usuário do banco com privilégios mínimos: SELECT/UPDATE em invoices,
  // INSERT em webhook_events. Nada além disso.
});

// ---------------------------------------------------------------------------
// Verificação de assinatura (A02 Cryptographic Failures / A07 Auth Failures)
// ---------------------------------------------------------------------------
function verifySignature(rawBody, header) {
  if (typeof header !== 'string' || header.length > 512) return false;

  const parts = Object.fromEntries(
    header.split(',').map((kv) => {
      const i = kv.indexOf('=');
      return i === -1 ? [kv.trim(), ''] : [kv.slice(0, i).trim(), kv.slice(i + 1).trim()];
    })
  );

  const timestamp = Number(parts.t);
  const received = parts.v1;
  if (!Number.isInteger(timestamp) || typeof received !== 'string') return false;
  if (!/^[0-9a-f]{64}$/i.test(received)) return false;

  // Anti-replay: rejeita mensagens fora da janela de tempo
  const age = Math.abs(Math.floor(Date.now() / 1000) - timestamp);
  if (age > TOLERANCE_SECONDS) return false;

  const receivedBuf = Buffer.from(received, 'hex');
  const signedPayload = Buffer.concat([Buffer.from(`${timestamp}.`), rawBody]);

  // Aceita qualquer segredo vigente (rotação sem downtime)
  return SECRETS.some((secret) => {
    const expected = crypto.createHmac('sha256', secret).update(signedPayload).digest();
    return expected.length === receivedBuf.length && crypto.timingSafeEqual(expected, receivedBuf);
  });
}

// ---------------------------------------------------------------------------
// Validação do payload (A03 Injection / A04 Insecure Design)
// Allowlist estrita: qualquer campo/forma inesperada é rejeitada.
// ---------------------------------------------------------------------------
const EVENT_TO_STATUS = Object.freeze({
  'invoice.paid': 'paid',
  'invoice.payment_failed': 'failed',
  'invoice.canceled': 'canceled',
  'invoice.refunded': 'refunded',
});

const payloadSchema = z.object({
  id: z.string().min(1).max(128).regex(/^[A-Za-z0-9_\-.:]+$/), // id único do evento
  type: z.string().min(1).max(64),
  data: z.object({
    invoice_id: z.string().min(1).max(128).regex(/^[A-Za-z0-9_\-.:]+$/), // id da fatura NO GATEWAY
    amount_cents: z.number().int().nonnegative().max(1_000_000_000_00),
    currency: z.string().length(3).regex(/^[A-Za-z]{3}$/),
  }),
});

// Máquina de estados: impede transições ilegítimas (ex.: reabrir fatura cancelada)
// e protege contra eventos fora de ordem.
const ALLOWED_TRANSITIONS = Object.freeze({
  pending: new Set(['paid', 'failed', 'canceled']),
  failed: new Set(['paid', 'canceled']),
  paid: new Set(['refunded']),
  canceled: new Set(),
  refunded: new Set(),
});

// ---------------------------------------------------------------------------
// Processamento transacional e idempotente
// ---------------------------------------------------------------------------
async function processEvent(event) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1) Idempotência: o event_id é UNIQUE. Se já existe, é reentrega.
    //    Como o INSERT está na mesma transação, uma falha posterior faz rollback
    //    e o gateway pode reenviar sem que o evento seja "perdido".
    const ins = await client.query(
      `INSERT INTO webhook_events (gateway, event_id, event_type, received_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (gateway, event_id) DO NOTHING`,
      [GATEWAY_NAME, event.id, event.type]
    );
    if (ins.rowCount === 0) {
      await client.query('COMMIT');
      return { outcome: 'duplicate' };
    }

    const newStatus = EVENT_TO_STATUS[event.type];
    if (!newStatus) {
      await client.query(
        `UPDATE webhook_events SET result = 'ignored_type' WHERE gateway = $1 AND event_id = $2`,
        [GATEWAY_NAME, event.id]
      );
      await client.query('COMMIT');
      return { outcome: 'ignored_type' };
    }

    // 2) A fatura é localizada pelo ID do gateway. O tenant_id NUNCA vem do
    //    payload: é derivado do registro da fatura (A01 Broken Access Control).
    //    FOR UPDATE serializa eventos concorrentes da mesma fatura.
    const { rows } = await client.query(
      `SELECT id, tenant_id, status, amount_cents, currency
         FROM invoices
        WHERE gateway = $1 AND gateway_invoice_id = $2
        FOR UPDATE`,
      [GATEWAY_NAME, event.data.invoice_id]
    );

    if (rows.length === 0) {
      await client.query(
        `UPDATE webhook_events SET result = 'invoice_not_found' WHERE gateway = $1 AND event_id = $2`,
        [GATEWAY_NAME, event.id]
      );
      await client.query('COMMIT');
      return { outcome: 'invoice_not_found' };
    }

    const invoice = rows[0];

    // 3) Conferência de integridade: valor e moeda devem bater com o que
    //    foi emitido pela plataforma (nunca confiar só no que o gateway diz).
    if (
      newStatus === 'paid' &&
      (Number(invoice.amount_cents) !== event.data.amount_cents ||
        invoice.currency.toUpperCase() !== event.data.currency.toUpperCase())
    ) {
      await client.query(
        `UPDATE webhook_events
            SET result = 'amount_mismatch', tenant_id = $3
          WHERE gateway = $1 AND event_id = $2`,
        [GATEWAY_NAME, event.id, invoice.tenant_id]
      );
      await client.query('COMMIT');
      return { outcome: 'amount_mismatch', invoiceId: invoice.id }; // alertar equipe
    }

    // 4) Transição de estado válida?
    const allowed = ALLOWED_TRANSITIONS[invoice.status];
    if (!allowed || !allowed.has(newStatus)) {
      await client.query(
        `UPDATE webhook_events
            SET result = 'invalid_transition', tenant_id = $3
          WHERE gateway = $1 AND event_id = $2`,
        [GATEWAY_NAME, event.id, invoice.tenant_id]
      );
      await client.query('COMMIT');
      return { outcome: 'invalid_transition' };
    }

    // 5) Atualização parametrizada, escopada por id + tenant_id (defesa em profundidade)
    await client.query(
      `UPDATE invoices
          SET status = $1,
              paid_at = CASE WHEN $1 = 'paid' THEN now() ELSE paid_at END,
              updated_at = now()
        WHERE id = $2 AND tenant_id = $3`,
      [newStatus, invoice.id, invoice.tenant_id]
    );

    await client.query(
      `UPDATE webhook_events
          SET result = 'applied', tenant_id = $3, processed_at = now()
        WHERE gateway = $1 AND event_id = $2`,
      [GATEWAY_NAME, event.id, invoice.tenant_id]
    );

    await client.query('COMMIT');
    return { outcome: 'applied', invoiceId: invoice.id, tenantId: invoice.tenant_id };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
const router = express.Router();

// A04: rate limit por IP (idealmente combinado com allowlist de IPs do gateway
// no WAF/proxy reverso).
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

router.post(
  '/webhooks/payments',
  webhookLimiter,
  // Corpo BRUTO: a assinatura é calculada sobre os bytes originais.
  // Este router deve ser montado ANTES de qualquer express.json() global.
  express.raw({ type: 'application/json', limit: MAX_BODY_BYTES }),
  async (req, res) => {
    // Rota máquina-a-máquina: sem cookies/sessão, sem CORS, sem CSRF aplicável.
    res.set('Cache-Control', 'no-store');

    // 1) Autenticidade ANTES de qualquer parsing
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    if (!verifySignature(req.body, req.get(SIGNATURE_HEADER))) {
      console.warn(JSON.stringify({ msg: 'webhook_signature_invalid', ip: req.ip }));
      return res.status(401).json({ error: 'invalid_signature' });
    }

    // 2) Parse + validação estrita
    let parsed;
    try {
      parsed = payloadSchema.strict().safeParse(JSON.parse(req.body.toString('utf8')));
    } catch {
      return res.status(400).json({ error: 'invalid_json' });
    }
    if (!parsed.success) {
      // Não devolve detalhes do schema ao chamador (A05)
      console.warn(JSON.stringify({ msg: 'webhook_payload_invalid', ip: req.ip }));
      return res.status(400).json({ error: 'invalid_payload' });
    }

    // 3) Processamento
    try {
      const result = await processEvent(parsed.data);

      // Log estruturado SEM payload bruto nem dados financeiros/PII (A09)
      console.info(
        JSON.stringify({
          msg: 'webhook_processed',
          eventId: parsed.data.id,
          eventType: parsed.data.type,
          outcome: result.outcome,
          tenantId: result.tenantId,
          invoiceId: result.invoiceId,
        })
      );

      if (result.outcome === 'amount_mismatch') {
        console.error(
          JSON.stringify({ msg: 'ALERT_amount_mismatch', eventId: parsed.data.id, invoiceId: result.invoiceId })
        );
      }

      // 2xx para tudo que foi tratado de forma definitiva (inclui duplicado/ignorado),
      // evitando que o gateway reenvie indefinidamente.
      return res.status(200).json({ received: true });
    } catch (err) {
      // Falha transitória: 500 faz o gateway reenviar. Sem stack trace na resposta (A05).
      console.error(
        JSON.stringify({ msg: 'webhook_processing_error', eventId: parsed.data.id, error: err.code || err.name })
      );
      return res.status(500).json({ error: 'internal_error' });
    }
  }
);

module.exports = router;

/* ---------------------------------------------------------------------------
 * Uso no app.js:
 *
 *   const helmet = require('helmet');
 *   const app = express();
 *   app.disable('x-powered-by');
 *   app.set('trust proxy', 1);            // ajuste conforme sua infraestrutura
 *   app.use(helmet());
 *   app.use(require('./routes/paymentWebhook')); // ANTES do express.json() global
 *   app.use(express.json({ limit: '1mb' }));
 *
 * ---------------------------------------------------------------------------
 * Esquema SQL mínimo (PostgreSQL):
 *
 *   CREATE TABLE invoices (
 *     id                  BIGSERIAL PRIMARY KEY,
 *     tenant_id           BIGINT NOT NULL REFERENCES tenants(id),
 *     gateway             TEXT   NOT NULL,
 *     gateway_invoice_id  TEXT   NOT NULL,
 *     amount_cents        BIGINT NOT NULL,
 *     currency            CHAR(3) NOT NULL,
 *     status              TEXT   NOT NULL DEFAULT 'pending'
 *                         CHECK (status IN ('pending','paid','failed','canceled','refunded')),
 *     paid_at             TIMESTAMPTZ,
 *     updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
 *     UNIQUE (gateway, gateway_invoice_id)
 *   );
 *   CREATE INDEX ON invoices (tenant_id);
 *
 *   CREATE TABLE webhook_events (
 *     id            BIGSERIAL PRIMARY KEY,
 *     gateway       TEXT NOT NULL,
 *     event_id      TEXT NOT NULL,
 *     event_type    TEXT NOT NULL,
 *     tenant_id     BIGINT,
 *     result        TEXT,
 *     received_at   TIMESTAMPTZ NOT NULL,
 *     processed_at  TIMESTAMPTZ,
 *     UNIQUE (gateway, event_id)
 *   );
 * ------------------------------------------------------------------------- */