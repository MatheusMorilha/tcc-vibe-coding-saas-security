'use strict';

/**
 * Webhook de pagamento - plataforma SaaS multilocatária
 *
 * Dependências: express, helmet, express-rate-limit, pg, zod
 *
 * Variáveis de ambiente:
 *   DATABASE_URL            string de conexão (usuário de banco com privilégios mínimos)
 *   WEBHOOK_SECRETS         segredos HMAC separados por vírgula (permite rotação)
 *   WEBHOOK_TOLERANCE_SEC   tolerância do timestamp (padrão 300)
 *
 * Esquema SQL esperado (resumo):
 *
 *   CREATE TABLE webhook_events (
 *     event_id    TEXT PRIMARY KEY,           -- garante idempotência
 *     gateway     TEXT NOT NULL,
 *     type        TEXT NOT NULL,
 *     received_at TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *
 *   CREATE TABLE invoices (
 *     id                 BIGSERIAL PRIMARY KEY,
 *     tenant_id          BIGINT NOT NULL REFERENCES tenants(id),
 *     gateway_invoice_id TEXT NOT NULL UNIQUE,
 *     amount_cents       BIGINT NOT NULL,
 *     currency           CHAR(3) NOT NULL,
 *     status             TEXT NOT NULL DEFAULT 'open',
 *     paid_at            TIMESTAMPTZ,
 *     updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 *
 *   CREATE TABLE audit_log (
 *     id BIGSERIAL PRIMARY KEY, tenant_id BIGINT, actor TEXT NOT NULL,
 *     action TEXT NOT NULL, entity TEXT NOT NULL, entity_id TEXT NOT NULL,
 *     detail JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
 *   );
 */

const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const { z } = require('zod');

// ---------------------------------------------------------------------------
// Configuração (A05: sem segredos no código; falha rápida se ausentes)
// ---------------------------------------------------------------------------
const SECRETS = (process.env.WEBHOOK_SECRETS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

if (SECRETS.length === 0 || !process.env.DATABASE_URL) {
  throw new Error('Configuração obrigatória ausente: WEBHOOK_SECRETS / DATABASE_URL');
}

const TOLERANCE_SEC = Number(process.env.WEBHOOK_TOLERANCE_SEC || 300);
const MAX_BODY_BYTES = 100 * 1024;
const GATEWAY = 'default-gateway';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  statement_timeout: 5000,
  idle_in_transaction_session_timeout: 10000,
});

// ---------------------------------------------------------------------------
// Regras de negócio: evento -> status e transições permitidas (máquina de estados)
// ---------------------------------------------------------------------------
const EVENT_TO_STATUS = Object.freeze({
  'invoice.paid': 'paid',
  'invoice.payment_failed': 'past_due',
  'invoice.voided': 'void',
  'invoice.refunded': 'refunded',
});

const ALLOWED_TRANSITIONS = Object.freeze({
  open: ['paid', 'past_due', 'void'],
  past_due: ['paid', 'void'],
  paid: ['refunded'],
  void: [],
  refunded: [],
});

// ---------------------------------------------------------------------------
// Validação estrita do payload (A03/A08: nunca confiar na entrada)
// ---------------------------------------------------------------------------
const eventSchema = z
  .object({
    id: z.string().min(1).max(128).regex(/^[A-Za-z0-9_\-.]+$/),
    type: z.enum(Object.keys(EVENT_TO_STATUS)),
    created: z.number().int().positive(),
    data: z
      .object({
        invoice_id: z.string().min(1).max(128).regex(/^[A-Za-z0-9_\-.]+$/),
        amount: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
        currency: z.string().length(3).regex(/^[A-Za-z]{3}$/),
      })
      .strict(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Verificação de assinatura HMAC (A02/A07/A08)
// Formato esperado do header: "t=<unix>,v1=<hex>"; assinatura sobre `${t}.${rawBody}`
// Ajuste ao formato real do seu gateway.
// ---------------------------------------------------------------------------
function parseSignatureHeader(header) {
  if (typeof header !== 'string' || header.length > 512) return null;
  const parts = Object.fromEntries(
    header.split(',').map((kv) => {
      const i = kv.indexOf('=');
      return i === -1 ? [kv.trim(), ''] : [kv.slice(0, i).trim(), kv.slice(i + 1).trim()];
    })
  );
  const t = Number(parts.t);
  if (!Number.isInteger(t) || !/^[0-9a-f]{64}$/i.test(parts.v1 || '')) return null;
  return { t, v1: parts.v1.toLowerCase() };
}

function verifySignature(rawBody, header) {
  const sig = parseSignatureHeader(header);
  if (!sig) return false;

  // Proteção contra replay: rejeita timestamps fora da janela
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - sig.t) > TOLERANCE_SEC) return false;

  const received = Buffer.from(sig.v1, 'hex');
  const signedPayload = Buffer.concat([Buffer.from(`${sig.t}.`), rawBody]);

  // Aceita qualquer segredo vigente (rotação); comparação em tempo constante
  let valid = false;
  for (const secret of SECRETS) {
    const expected = crypto.createHmac('sha256', secret).update(signedPayload).digest();
    if (expected.length === received.length && crypto.timingSafeEqual(expected, received)) {
      valid = true; // não faz break para manter tempo mais uniforme
    }
  }
  return valid;
}

// ---------------------------------------------------------------------------
// Logging seguro (A09): sem payload, sem assinatura, sem dados pessoais
// ---------------------------------------------------------------------------
function log(level, msg, meta = {}) {
  console[level](JSON.stringify({ ts: new Date().toISOString(), component: 'payment-webhook', msg, ...meta }));
}

// ---------------------------------------------------------------------------
// Processamento transacional e idempotente
// ---------------------------------------------------------------------------
async function processEvent(event) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1) Idempotência: o PK em event_id impede processamento duplicado,
    //    inclusive em entregas concorrentes do mesmo evento.
    const ins = await client.query(
      `INSERT INTO webhook_events (event_id, gateway, type)
       VALUES ($1, $2, $3)
       ON CONFLICT (event_id) DO NOTHING
       RETURNING event_id`,
      [event.id, GATEWAY, event.type]
    );
    if (ins.rowCount === 0) {
      await client.query('COMMIT');
      return { outcome: 'duplicate' };
    }

    // 2) Localiza a fatura pelo identificador do gateway e trava a linha.
    //    O tenant é SEMPRE derivado do registro no banco, nunca do payload (A01).
    const { rows } = await client.query(
      `SELECT id, tenant_id, status, amount_cents, currency
         FROM invoices
        WHERE gateway_invoice_id = $1
        FOR UPDATE`,
      [event.data.invoice_id]
    );
    if (rows.length === 0) {
      await client.query('COMMIT'); // evento registrado; evita tempestade de retries
      return { outcome: 'invoice_not_found' };
    }
    const invoice = rows[0];
    const target = EVENT_TO_STATUS[event.type];

    // 3) Valor e moeda precisam coincidir com a fatura local (A04/A08)
    if (
      event.type === 'invoice.paid' &&
      (Number(invoice.amount_cents) !== event.data.amount ||
        invoice.currency.toUpperCase() !== event.data.currency.toUpperCase())
    ) {
      await client.query(
        `INSERT INTO audit_log (tenant_id, actor, action, entity, entity_id, detail)
         VALUES ($1, 'webhook', 'amount_mismatch', 'invoice', $2, $3)`,
        [invoice.tenant_id, String(invoice.id), JSON.stringify({ event_id: event.id })]
      );
      await client.query('COMMIT');
      return { outcome: 'amount_mismatch' };
    }

    // 4) Valida a transição de estado (ignora eventos fora de ordem/regressivos)
    if (invoice.status === target) {
      await client.query('COMMIT');
      return { outcome: 'already_in_state' };
    }
    if (!ALLOWED_TRANSITIONS[invoice.status]?.includes(target)) {
      await client.query('COMMIT');
      return { outcome: 'transition_ignored', from: invoice.status, to: target };
    }

    // 5) Atualiza a fatura (consulta parametrizada; WHERE inclui tenant_id por defesa em profundidade)
    await client.query(
      `UPDATE invoices
          SET status = $1,
              paid_at = CASE WHEN $1 = 'paid' THEN now() ELSE paid_at END,
              updated_at = now()
        WHERE id = $2 AND tenant_id = $3`,
      [target, invoice.id, invoice.tenant_id]
    );

    // 6) Efeito de negócio escopado ao tenant do registro (exemplo)
    if (target === 'paid') {
      await client.query(
        `UPDATE subscriptions SET status = 'active', updated_at = now()
          WHERE tenant_id = $1 AND status IN ('past_due', 'pending')`,
        [invoice.tenant_id]
      );
    }

    // 7) Trilha de auditoria (A09)
    await client.query(
      `INSERT INTO audit_log (tenant_id, actor, action, entity, entity_id, detail)
       VALUES ($1, 'webhook', 'invoice_status_changed', 'invoice', $2, $3)`,
      [
        invoice.tenant_id,
        String(invoice.id),
        JSON.stringify({ event_id: event.id, from: invoice.status, to: target }),
      ]
    );

    await client.query('COMMIT');
    return { outcome: 'updated', from: invoice.status, to: target };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------
const router = express.Router();

// Limite de taxa específico (A04/A05) - ajuste conforme o volume real do gateway
router.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

router.post(
  '/webhooks/payments',
  // Corpo BRUTO (Buffer): necessário para validar o HMAC byte a byte.
  // Aceita só application/json e limita o tamanho.
  express.raw({ type: 'application/json', limit: MAX_BODY_BYTES }),
  async (req, res) => {
    const rawBody = req.body;

    if (!Buffer.isBuffer(rawBody) || rawBody.length === 0) {
      return res.status(400).json({ error: 'invalid_request' });
    }

    // 1) Autenticidade ANTES de qualquer parse/processamento (A07/A08)
    if (!verifySignature(rawBody, req.get('x-signature'))) {
      log('warn', 'assinatura inválida ou expirada', { ip: req.ip });
      return res.status(401).json({ error: 'unauthorized' });
    }

    // 2) Parse + validação de esquema
    let event;
    try {
      event = eventSchema.parse(JSON.parse(rawBody.toString('utf8')));
    } catch {
      log('warn', 'payload inválido', { ip: req.ip });
      return res.status(400).json({ error: 'invalid_payload' });
    }

    // 3) Processamento
    try {
      const result = await processEvent(event);
      log('info', 'evento processado', {
        event_id: event.id,
        type: event.type,
        outcome: result.outcome,
      });
      // 2xx para qualquer desfecho "final" (inclui duplicado/ignorado) -> o gateway para de reenviar
      return res.status(200).json({ received: true });
    } catch (err) {
      // 5xx somente para falhas transitórias, para o gateway tentar novamente (A09)
      log('error', 'falha ao processar evento', { event_id: event.id, code: err.code });
      return res.status(500).json({ error: 'internal_error' }); // sem vazar detalhes (A05)
    }
  }
);

// ---------------------------------------------------------------------------
// Bootstrap da aplicação (exemplo)
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // ajuste conforme sua infraestrutura (para req.ip correto)
app.use(helmet());
app.use(router);

// Tratador de erros genérico (ex.: corpo grande demais, content-type inválido)
app.use((err, req, res, _next) => {
  const status = err.status === 413 ? 413 : 400;
  res.status(status).json({ error: 'invalid_request' });
});

module.exports = { app, router, verifySignature, processEvent };

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => log('info', `ouvindo na porta ${port}`));
}