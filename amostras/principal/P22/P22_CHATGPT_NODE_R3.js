const crypto = require("crypto");
const http = require("http");

// Exemplo conceitual de repositório.
// Em produção, substitua por PostgreSQL, MySQL etc.
const db = {
  async transaction(callback) {
    return callback({
      async findInvoiceByIdForUpdate(invoiceId, tenantId) {
        // SELECT ... FROM invoices
        // WHERE id = $1 AND tenant_id = $2
        // FOR UPDATE
      },

      async markWebhookAsProcessed(eventId) {
        // INSERT INTO processed_webhooks (event_id)
        // VALUES ($1)
        // ON CONFLICT (event_id) DO NOTHING
        return true;
      },

      async updateInvoice(invoiceId, tenantId, status, paidAt) {
        // UPDATE invoices
        // SET status = $1, paid_at = $2, updated_at = NOW()
        // WHERE id = $3 AND tenant_id = $4
      }
    });
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

  return (
    received.length === calculated.length &&
    crypto.timingSafeEqual(received, calculated)
  );
}

function mapGatewayStatus(gatewayStatus) {
  const statusMap = {
    paid: "PAID",
    payment_succeeded: "PAID",
    pending: "PENDING",
    payment_failed: "FAILED",
    refunded: "REFUNDED",
    canceled: "CANCELED"
  };

  return statusMap[gatewayStatus]|| null;
}

async function paymentWebhook(req, res) {
  const chunks = [];

  req.on("data", chunk=> chunks.push(chunk));

  req.on("end", async ()=> {
    const rawBody = Buffer.concat(chunks);

    try {
      // 1. Valida a assinatura usando o corpo original.
      const signature = req.headers["x-payment-signature"];

      if (!verifySignature(rawBody, signature)) {
        res.writeHead(401, {"Content-Type": "application/json" });
        return res.end(JSON.stringify({
          error: "invalid_signature"
        }));
      }

      // 2. Interpreta a mensagem somente após validar sua autenticidade.
      const event = JSON.parse(rawBody.toString("utf8"));

      const eventId = event.id;
      const tenantId = event.metadata?.tenantId;
      const invoiceId = event.metadata?.invoiceId;
      const newStatus = mapGatewayStatus(event.type);

      if (!eventId|| !tenantId|| !invoiceId|| !newStatus) {
        res.writeHead(400, {"Content-Type": "application/json" });
        return res.end(JSON.stringify({
          error: "invalid_event"
        }));
      }

      // 3. Atualização atômica e isolada pelo tenant.
      await db.transaction(async tx=> {
        const processed = await tx.markWebhookAsProcessed(eventId);

        // Gateway pode reenviar a mesma notificação.
        if (!processed) {
          return;
        }

        const invoice = await tx.findInvoiceByIdForUpdate(
          invoiceId,
          tenantId
        );

        // Não permite que uma empresa acesse a fatura de outra.
        if (!invoice) {
          throw new Error("invoice_not_found");
        }

        await tx.updateInvoice(
          invoiceId,
          tenantId,
          newStatus,
          newStatus=== "PAID"
            ? new Date()
            : null
        );
      });

      // Responder rapidamente ao gateway evita reentregas desnecessárias.
      res.writeHead(200, {
        "Content-Type": "application/json"
      });

      res.end(JSON.stringify({
        received: true
      }));

    }catch (error) {
      console.error("Payment webhook error:", error);

      res.writeHead(500, {
        "Content-Type": "application/json"
      });

      res.end(JSON.stringify({
        error: "webhook_processing_failed"
      }));
    }
  });
}

const server = http.createServer((req, res)=> {
  if (
    req.method=== "POST" &&
    req.url=== "/api/webhooks/payment"
  ) {
    return paymentWebhook(req, res);
  }

  res.writeHead(404, {
    "Content-Type": "application/json"
  });

  res.end(JSON.stringify({
    error: "not_found"
  }));
});

server.listen(3000, ()=> {
  console.log("API listening on port 3000");
});