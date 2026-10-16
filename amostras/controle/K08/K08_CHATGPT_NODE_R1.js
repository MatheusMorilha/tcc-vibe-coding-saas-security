'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 3000);
const WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET;

if (!WEBHOOK_SECRET) {
  throw new Error('PAYMENT_WEBHOOK_SECRET não configurado');
}

/*
 * Interfaces que devem ser implementadas pelo seu repositório/ORM.
 *
 * IMPORTANTE:
 * A atualização da fatura e o registro do evento devem ocorrer
 * na MESMA transação do banco.
 */
const db = {
  async transaction(callback) {
    // Substituir pela implementação real.
    // callback recebe uma conexão/transação.
    return callback({});
  },

  async findInvoiceByGatewayId(tx, gatewayInvoiceId) {
    // SELECT ... FOR UPDATE
    throw new Error('Implementar findInvoiceByGatewayId');
  },

  async eventWasProcessed(tx, eventId) {
    throw new Error('Implementar eventWasProcessed');
  },

  async registerEvent(tx, event) {
    // Deve existir uma UNIQUE(event_id).
    throw new Error('Implementar registerEvent');
  },

  async updateInvoiceStatus(tx, invoiceId, status, gatewayEventId) {
    throw new Error('Implementar updateInvoiceStatus');
  }
};

const ALLOWED_STATUSES = new Set([
  'pending',
  'paid',
  'failed',
  'cancelled',
  'refunded'
]);

const MAX_BODY_SIZE = 1024 * 1024; // 1 MiB

function safeEqual(a, b) {
  const aBuffer = Buffer.from(a, 'utf8');
  const bBuffer = Buffer.from(b, 'utf8');

  if (aBuffer.length !== bBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(aBuffer, bBuffer);
}

/*
 * Exemplo de assinatura:
 *
 * X-Webhook-Signature: sha256=<hex>
 *
 * O gateway deve assinar o corpo RAW da requisição.
 */
function verifySignature(rawBody, signatureHeader) {
  if (!signatureHeader) {
    return false;
  }

  const prefix = 'sha256=';

  if (!signatureHeader.startsWith(prefix)) {
    return false;
  }

  const receivedSignature = signatureHeader.slice(prefix.length);

  if (!/^[a-f0-9]{64}$/i.test(receivedSignature)) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');

  return safeEqual(
    receivedSignature.toLowerCase(),
    expectedSignature.toLowerCase()
  );
}

function parseJson(rawBody) {
  try {
    return JSON.parse(rawBody.toString('utf8'));
  } catch {
    const error = new Error('Invalid JSON');
    error.statusCode = 400;
    throw error;
  }
}

/*
 * Adapte este normalizador ao formato real do gateway.
 *
 * Exemplo de payload:
 *
 * {
 *   "id": "evt_123",
 *   "type": "invoice.paid",
 *   "data": {
 *     "invoice": {
 *       "id": "inv_123",
 *       "status": "paid"
 *     }
 *   }
 * }
 */
function normalizeGatewayEvent(payload) {
  if (
    !payload ||
    typeof payload !== 'object' ||
    typeof payload.id !== 'string' ||
    typeof payload.type !== 'string'
  ) {
    const error = new Error('Invalid webhook structure');
    error.statusCode = 400;
    throw error;
  }

  const invoice = payload.data?.invoice;

  if (
    !invoice ||
    typeof invoice.id !== 'string' ||
    typeof invoice.status !== 'string'
  ) {
    const error = new Error('Missing invoice information');
    error.statusCode = 400;
    throw error;
  }

  const status = invoice.status.toLowerCase();

  if (!ALLOWED_STATUSES.has(status)) {
    const error = new Error('Unsupported invoice status');
    error.statusCode = 400;
    throw error;
  }

  return {
    eventId: payload.id,
    eventType: payload.type,
    gatewayInvoiceId: invoice.id,
    status
  };
}

function sendJson(res, statusCode, body) {
  const response = JSON.stringify(body);

  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });

  res.end(response);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let totalBytes = 0;
    const chunks = [];

    req.on('data', chunk => {
      totalBytes += chunk.length;

      if (totalBytes > MAX_BODY_SIZE) {
        const error = new Error('Payload too large');
        error.statusCode = 413;

        req.destroy(error);
        reject(error);
        return;
      }

      chunks.push(chunk);
    });

    req.on('end', () => {
      resolve(Buffer.concat(chunks));
    });

    req.on('error', reject);
  });
}

async function paymentWebhookHandler(req, res) {
  if (req.method !== 'POST') {
    return sendJson(res, 405, {
      error: 'method_not_allowed'
    });
  }

  const contentType = req.headers['content-type'] || '';

  if (!contentType.toLowerCase().startsWith('application/json')) {
    return sendJson(res, 415, {
      error: 'unsupported_media_type'
    });
  }

  let rawBody;

  try {
    rawBody = await readRawBody(req);
  } catch (error) {
    const status = error.statusCode || 400;

    return sendJson(res, status, {
      error: status === 413
        ? 'payload_too_large'
        : 'invalid_request'
    });
  }

  /*
   * Verificar a assinatura ANTES de confiar no conteúdo recebido.
   */
  const signature = req.headers['x-webhook-signature'];

  if (!verifySignature(rawBody, signature)) {
    return sendJson(res, 401, {
      error: 'invalid_signature'
    });
  }

  let payload;

  try {
    payload = parseJson(rawBody);
  } catch (error) {
    return sendJson(res, error.statusCode || 400, {
      error: 'invalid_payload'
    });
  }

  let event;

  try {
    event = normalizeGatewayEvent(payload);
  } catch (error) {
    return sendJson(res, error.statusCode || 400, {
      error: 'invalid_webhook'
    });
  }

  try {
    await db.transaction(async tx => {
      /*
       * Idempotência:
       *
       * Gateways normalmente podem reenviar o mesmo webhook.
       * O event_id precisa ter UNIQUE constraint no banco.
       */
      if (await db.eventWasProcessed(tx, event.eventId)) {
        return;
      }

      /*
       * Localizamos a fatura pelo ID fornecido pelo gateway.
       *
       * Não confiamos em tenant_id enviado pelo cliente.
       * O tenant deve ser descoberto a partir da própria fatura.
       */
      const invoice = await db.findInvoiceByGatewayId(
        tx,
        event.gatewayInvoiceId
      );

      if (!invoice) {
        const error = new Error('Invoice not found');
        error.statusCode = 404;
        throw error;
      }

      /*
       * A consulta deve usar SELECT ... FOR UPDATE ou equivalente,
       * evitando condições de corrida entre webhooks simultâneos.
       */

      await db.updateInvoiceStatus(
        tx,
        invoice.id,
        event.status,
        event.eventId
      );

      await db.registerEvent(tx, {
        eventId: event.eventId,
        eventType: event.eventType,
        invoiceId: invoice.id,
        receivedAt: new Date()
      });
    });

    return sendJson(res, 200, {
      received: true
    });
  } catch (error) {
    /*
     * Não retornamos stack trace, SQL, IDs internos ou detalhes
     * de infraestrutura ao gateway.
     */
    if (error.statusCode === 404) {
      return sendJson(res, 404, {
        error: 'invoice_not_found'
      });
    }

    /*
     * Erros inesperados devem ser registrados internamente,
     * com correlação/event_id, sem vazar detalhes para o cliente.
     */
    console.error('Payment webhook processing failed', {
      eventId: event.eventId,
      error: error.message
    });

    return sendJson(res, 500, {
      error: 'internal_error'
    });
  }
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.url === '/webhooks/payment') {
      await paymentWebhookHandler(req, res);
      return;
    }

    sendJson(res, 404, {
      error: 'not_found'
    });
  } catch (error) {
    console.error('Unhandled request error', error);

    if (!res.headersSent) {
      sendJson(res, 500, {
        error: 'internal_error'
      });
    }
  }
});

server.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
