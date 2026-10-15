const http = require("http");
const crypto = require("crypto");

// Exemplo de persistência.
// Em produção, substitua por seu driver/ORM e use transações do banco.
const db = {
  async findInvoiceById(id) {
    // SELECT ... FROM invoices WHERE id = ?
  },

  async updateInvoice(id, data) {
    // UPDATE invoices SET ... WHERE id = ?
  },

  async webhookAlreadyProcessed(eventId) {
    // SELECT id FROM processed_webhooks WHERE event_id = ?
  },

  async markWebhookAsProcessed(eventId) {
    // INSERT INTO processed_webhooks (event_id) VALUES (?)
  }
};

const WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET;

function verifySignature(rawBody, signature) {
  if (!signature|| !WEBHOOK_SECRET) {
    return false;
  }

  const expected = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(rawBody)
    .digest("hex");

  const received = Buffer.from(signature, "utf8");
  const calculated = Buffer.from(expected, "utf8");

  if (received.length !== calculated.length) {
    return false;
  }

  return crypto.timingSafeEqual(received, calculated);
}

function normalizeInvoiceStatus(paymentStatus) {
  const statuses = {
    paid: "PAID",
    approved: "PAID",
    pending: "PENDING",
    processing: "PENDING",
    failed: "FAILED",
    cancelled: "CANCELLED",
    refunded: "REFUNDED"
  };

  return statuses[paymentStatus];
}

async function readBody(req) {
  const chunks = [];

  for await (const chunk of req) {
    chunks.push(chunk);
  }

  return Buffer.concat(chunks);
}

async function paymentWebhook(req, res) {
  try {
    if (req.method!== "POST" || req.url!== "/webhooks/payment") {
      res.writeHead(404);
      return res.end("Not found");
    }

    const rawBody = await readBody(req);

    // A assinatura deve ser validada sobre o payload original,
    // antes de JSON.parse().
    const signature = req.headers["x-payment-signature"];

    if (!verifySignature(rawBody, signature)) {
      res.writeHead(401, {
        "Content-Type": "application/json"
      });

      return res.end(JSON.stringify({
        error: "Invalid signature"
      }));
    }

    let event;

    try {
      event= JSON.parse(rawBody.toString("utf8"));
    }catch {
      res.writeHead(400, {
        "Content-Type": "application/json"
      });

      return res.end(JSON.stringify({
        error: "Invalid JSON"
      }));
    }

    const {
      id:eventId,
      type,
      tenantId,
      invoiceId,
      payment
    }= event;

    if (!eventId|| !tenantId|| !invoiceId|| !payment) {
      res.writeHead(400, {
        "Content-Type": "application/json"
      });

      return res.end(JSON.stringify({
        error: "Missing required fields"
      }));
    }

    // Webhooks podem ser reenviados pelo gateway.
    // O evento é processado somente uma vez.
    if (await db.webhookAlreadyProcessed(eventId)) {
      res.writeHead(200, {
        "Content-Type": "application/json"
      });

      return res.end(JSON.stringify({
        received: true,
        duplicate: true
      }));
    }

    const newStatus = normalizeInvoiceStatus(payment.status);

    if (!newStatus) {
      res.writeHead(422, {
        "Content-Type": "application/json"
      });

      return res.end(JSON.stringify({
        error: "Unsupported payment status"
      }));
    }

    /*
     * IMPORTANTE:
     * O tenantId recebido pelo gateway é utilizado junto ao invoiceId.
     *
     * Nunca faça:
     *
     *   SELECT * FROM invoices WHERE id = invoiceId
     *
     * isoladamente, pois isso poderia permitir que um evento de um
     * tenant alterasse uma fatura pertencente a outro tenant.
     */
    const invoice = await db.findInvoiceById({
      id: invoiceId,
      tenantId
    });

    if (!invoice) {
      res.writeHead(404, {
        "Content-Type": "application/json"
      });

      return res.end(JSON.stringify({
        error: "Invoice not found"
      }));
    }

    /*
     * A operação abaixo deve ocorrer em uma transação:
     *
     * 1. registrar o webhook;
     * 2. atualizar a fatura;
     *
     * Assim, o evento não fica marcado como processado caso a atualização
     * da fatura falhe.
     *
     * O método updateInvoice deve também validar tenantId.
     */
    await db.updateInvoice(invoiceId, {
      tenantId,
      status: newStatus,
      paymentId: payment.id,
      paidAt: newStatus=== "PAID"
        ? new Date()
        : null,
      gatewayStatus: payment.status,
      updatedAt: new Date()
    });

    await db.markWebhookAsProcessed(eventId);

    res.writeHead(200, {
      "Content-Type": "application/json"
    });

    return res.end(JSON.stringify({
      received: true
    }));

  }catch (error) {
    console.error("Payment webhook error:", error);

    /*
     * Retornar 5xx permite que gateways que possuem retry
     * reenviem a notificação.
     */
    res.writeHead(500, {
      "Content-Type": "application/json"
    });

    return res.end(JSON.stringify({
      error: "Internal server error"
    }));
  }
}

const server = http.createServer(paymentWebhook);

server.listen(process.env.PORT || 3000, ()=> {
  console.log("Payment webhook listening");
});