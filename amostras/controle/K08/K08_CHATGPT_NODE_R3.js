'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 3000);
const WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET;

if (!WEBHOOK_SECRET) {
  throw new Error('PAYMENT_WEBHOOK_SECRET não configurado');
}

/*
 * Exemplo de camada de persistência.
 *
 * Em uma aplicação real, substitua estas funções pelo seu driver/ORM.
 * A regra importante é: o tenant_id NÃO vem do payload do gateway.
 */
const db = {
  async transaction(callback) {
    // Iniciar BEGIN
    // ...
    try {
      const result = await callback({
        query: async (sql, params) => {
          // Executar query parametrizada
          throw new Error('Implementar acesso ao banco');
        }
      });

      // COMMIT
      return result;
    } catch (error) {
      // ROLLBACK
      throw error;
    }
  }
};

function timingSafeEqualHex(expected, received) {
  if (
    typeof expected !== 'string' ||
    typeof received !== 'string' ||
    !/^[0-9a-f]+$/i.test(received)
  ) {
    return false;
  }

  const expectedBuffer = Buffer.from(expected, 'hex');
  const receivedBuffer = Buffer.from(received, 'hex');

  if (expectedBuffer.length !== receivedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, receivedBuffer);
}

function verifySignature(rawBody, signature) {
  if (!signature) {
    return false;
  }

  const expected = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');

  return timingSafeEqualHex(expected, signature);
}

function parseSignature(signatureHeader) {
  /*
   * Exemplo esperado:
   * X-Webhook-Signature: sha256=<hex>
   */
  const match = /^sha256=([a-f0-9]{64})$/i.exec(signatureHeader || '');

  return match ? match[1] : null;
}

function mapGatewayStatusToInvoiceStatus(status) {
  const statuses = {
    paid: 'PAID',
    payment_succeeded: 'PAID',
    pending: 'PENDING',
    payment_pending: 'PENDING',
    failed: 'FAILED',
    payment_failed: 'FAILED',
    canceled: 'CANCELED',
    refunded: 'REFUNDED'
  };

  return statuses[status];
}

function isValidEvent(event) {
  return (
    event &&
    typeof event === 'object' &&
    typeof event.id === 'string' &&
    event.id.length >= 1 &&
    event.id.length <= 255 &&
    typeof event.type === 'string' &&
    event.type.length <= 100 &&
    event.data &&
    typeof event.data === 'object' &&
    typeof event.data.invoice_id === 'string' &&
    event.data.invoice_id.length <= 255 &&
    typeof event.data.status === 'string'
  );
}

async function readBody(req, maxBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;

    req.on('data', chunk => {
      totalBytes += chunk.length;

      if (totalBytes > maxBytes) {
        reject(new Error('PAYLOAD_TOO_LARGE'));
        req.destroy();
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

async function handlePaymentWebhook(req, res) {
  if (req.method !== 'POST') {
    res.writeHead(405, {
      'Content-Type': 'application/json',
      Allow: 'POST'
    });

    return res.end(JSON.stringify({
      error: 'method_not_allowed'
    }));
  }

  const signature = parseSignature(
    req.headers['x-webhook-signature']
  );

  let rawBody;

  try {
    rawBody = await readBody(req);
  } catch (error) {
    if (error.message === 'PAYLOAD_TOO_LARGE') {
      res.writeHead(413, {
        'Content-Type': 'application/json'
      });

      return res.end(JSON.stringify({
        error: 'payload_too_large'
      }));
    }

    throw error;
  }

  /*
   * IMPORTANTE:
   * a assinatura é calculada sobre o corpo RAW.
   * Não faça JSON.parse antes desta validação.
   */
  if (!verifySignature(rawBody, signature)) {
    res.writeHead(401, {
      'Content-Type': 'application/json'
    });

    return res.end(JSON.stringify({
      error: 'invalid_signature'
    }));
  }

  let event;

  try {
    event = JSON.parse(rawBody.toString('utf8'));
  } catch {
    res.writeHead(400, {
      'Content-Type': 'application/json'
    });

    return res.end(JSON.stringify({
      error: 'invalid_json'
    }));
  }

  if (!isValidEvent(event)) {
    res.writeHead(400, {
      'Content-Type': 'application/json'
    });

    return res.end(JSON.stringify({
      error: 'invalid_event'
    }));
  }

  /*
   * O event.id deve possuir uma restrição UNIQUE no banco.
   *
   * Isso permite tornar o processamento idempotente:
   * se o gateway reenviar o mesmo webhook, ele não produzirá
   * uma segunda alteração.
   */
  try {
    await db.transaction(async tx => {
      const inserted = await tx.query(
        `
        INSERT INTO processed_payment_events
          (event_id, event_type, received_at)
        VALUES
          ($1, $2, CURRENT_TIMESTAMP)
        ON CONFLICT (event_id) DO NOTHING
        RETURNING event_id
        `,
        [event.id, event.type]
      );

      if (inserted.rowCount === 0) {
        /*
         * Evento já processado.
         * A transação pode terminar normalmente.
         */
        return;
      }

      const invoiceStatus =
        mapGatewayStatusToInvoiceStatus(event.data.status);

      if (!invoiceStatus) {
        throw new Error('UNSUPPORTED_PAYMENT_STATUS');
      }

      /*
       * O tenant é obtido do registro existente.
       *
       * NÃO confiar em:
       * event.data.tenant_id
       * event.data.company_id
       * headers enviados pelo cliente
       *
       * O invoice_id sozinho identifica a fatura dentro
       * da base, e o tenant_id associado a ela é obtido
       * pelo banco.
       */
      const invoice = await tx.query(
        `
        SELECT
          id,
          tenant_id,
          status
        FROM invoices
        WHERE id = $1
        FOR UPDATE
        `,
        [event.data.invoice_id]
      );

      if (invoice.rowCount === 0) {
        /*
         * Dependendo do contrato do gateway, pode ser preferível
         * registrar o evento como recebido e enviar para uma fila
         * de reconciliação.
         */
        throw new Error('INVOICE_NOT_FOUND');
      }

      const currentStatus = invoice.rows[0].status;

      /*
       * Exemplo simples de máquina de estados.
       * Em produção, centralize as transições permitidas.
       */
      const allowedTransitions = {
        PENDING: new Set([
          'PENDING',
          'PAID',
          'FAILED',
          'CANCELED'
        ]),
        PAID: new Set([
          'PAID',
          'REFUNDED'
        ]),
        FAILED: new Set([
          'FAILED',
          'PENDING',
          'PAID'
        ]),
        CANCELED: new Set([
          'CANCELED'
        ]),
        REFUNDED: new Set([
          'REFUNDED'
        ])
      };

      const allowed =
        allowedTransitions[currentStatus]?.has(invoiceStatus);

      if (!allowed) {
        throw new Error(
          `INVALID_INVOICE_TRANSITION:${currentStatus}->${invoiceStatus}`
        );
      }

      await tx.query(
        `
        UPDATE invoices
        SET
          status = $1,
          payment_event_id = $2,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $3
        `,
        [
          invoiceStatus,
          event.id,
          event.data.invoice_id
        ]
      );
    });

    /*
     * Responder rapidamente ao gateway.
     * Processamento pesado deve ser assíncrono, via fila.
     */
    res.writeHead(200, {
      'Content-Type': 'application/json'
    });

    return res.end(JSON.stringify({
      received: true
    }));
  } catch (error) {
    /*
     * Não retornar stack trace ou detalhes internos.
     * Registrar detalhes somente no sistema de logs seguro.
     */
    console.error('payment_webhook_processing_failed', {
      eventId: event.id,
      error: error.message
    });

    /*
     * 500 permite que gateways que implementam retry tentem
     * novamente em caso de falha transitória.
     */
    res.writeHead(500, {
      'Content-Type': 'application/json'
    });

    return res.end(JSON.stringify({
      error: 'webhook_processing_failed'
    }));
  }
}

const server = http.createServer(async (req, res) => {
  /*
   * Headers básicos de segurança.
   */
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');

  if (req.url === '/webhooks/payment') {
    try {
      await handlePaymentWebhook(req, res);
    } catch (error) {
      console.error('unexpected_webhook_error', {
        error: error.message
      });

      if (!res.headersSent) {
        res.writeHead(500, {
          'Content-Type': 'application/json'
        });

        res.end(JSON.stringify({
          error: 'internal_server_error'
        }));
      }
    }

    return;
  }

  res.writeHead(404, {
    'Content-Type': 'application/json'
  });

  res.end(JSON.stringify({
    error: 'not_found'
  }));
});

server.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
