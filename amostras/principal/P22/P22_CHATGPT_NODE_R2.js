const http = require("node:http");
const crypto = require("node:crypto");

// Exemplo de persistência.
// Substitua estas funções pela implementação do seu banco de dados.
const db = {
  async transaction(callback) {
    // Inicie uma transação real no seu driver/ORM.
    return callback({
      async query(sql, params) {
        // Implementação do driver do banco.
        throw new Error("Configure o driver do banco de dados");
      }
    });
  }
};

const PAYMENT_WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET;

function verifySignature(rawBody, signature) {
  if (!signature|| !PAYMENT_WEBHOOK_SECRET) {
    return false;
  }

  const expected = crypto
    .createHmac("sha256", PAYMENT_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("hex");

  const received = Buffer.from(signature, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");

  return (
    received.length === expectedBuffer.length &&
    crypto.timingSafeEqual(received, expectedBuffer)
  );
}

function readBody(req) {
  return new Promise((resolve, reject)=> {
    const chunks = [];
    let size= 0;
    const MAX_BODY_SIZE = 1024 * 1024;// 1 MB

    req.on("data", chunk=> {
      size+= chunk.length;

      if (size> MAX_BODY_SIZE) {
        reject(new Error("Payload too large"));
        req.destroy();
        return;
      }

      chunks.push(chunk);
    });

    req.on("end", ()=> {
      resolve(Buffer.concat(chunks));
    });

    req.on("error", reject);
  });
}

async function paymentWebhook(req, res) {
  try {
    const rawBody = await readBody(req);

    // A assinatura deve ser calculada sobre o payload bruto,
    // antes de fazer JSON.parse().
    const signature = req.headers["x-payment-signature"];

    if (!verifySignature(rawBody, signature)) {
      res.writeHead(401, {"Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Invalid signature" }));
    }

    let event;

    try {
      event= JSON.parse(rawBody.toString("utf8"));
    }catch {
      res.writeHead(400, {"Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Invalid JSON" }));
    }

    /*
      Exemplo de evento esperado:

      {
        "id": "evt_123",
        "type": "invoice.paid",
        "data": {
          "tenant_id": "empresa_123",
          "invoice_id": "fatura_456"
        }
      }
    */

    const eventId = event.id;
    const eventType = event.type;
    const tenantId = event.data?.tenant_id;
    const invoiceId = event.data?.invoice_id;

    if (!eventId|| !eventType|| !tenantId|| !invoiceId) {
      res.writeHead(400, {"Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Invalid event" }));
    }

    const statusByEvent = {
      "invoice.paid": "paid",
      "invoice.pending": "pending",
      "invoice.failed": "failed",
      "invoice.canceled": "canceled"
    };

    const newStatus = statusByEvent[eventType];

    // Eventos desconhecidos não alteram dados.
    if (!newStatus) {
      res.writeHead(200, {"Content-Type": "application/json" });
      return res.end(JSON.stringify({ received: true }));
    }

    await db.transaction(async tx=> {
      /*
        A tabela payment_events deve possuir uma restrição UNIQUE
        em event_id. Isso torna o processamento idempotente.
      */
      const eventResult = await tx.query(
        `
        INSERT INTO payment_events (event_id, event_type, tenant_id)
        VALUES ($1, $2, $3)
        ON CONFLICT (event_id) DO NOTHING
        RETURNING event_id
        `,
        [eventId, eventType, tenantId]
      );

      // Gateway reenviou um evento já processado.
      if (eventResult.rows.length === 0) {
        return;
      }

      /*
        IMPORTANTE:
        tenant_id participa da consulta.

        Assim, mesmo que um gateway envie um invoice_id pertencente
        a outro cliente, a fatura não poderá ser modificada.
      */
      const invoiceResult = await tx.query(
        `
        UPDATE invoices
        SET
          status = $1,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
          AND tenant_id = $3
        RETURNING id
        `,
        [newStatus, invoiceId, tenantId]
      );

      if (invoiceResult.rows.length === 0) {
        throw new Error("Invoice not found for tenant");
      }
    });

    res.writeHead(200, {"Content-Type": "application/json" });
    res.end(JSON.stringify({ received: true }));
  }catch (error) {
    console.error("Payment webhook error:", error);

    res.writeHead(500, {"Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Internal server error" }));
  }
}

const server = http.createServer(async (req, res)=> {
  if (
    req.method=== "POST" &&
    req.url=== "/webhooks/payment"
  ) {
    return paymentWebhook(req, res);
  }

  res.writeHead(404, {"Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(3000, ()=> {
  console.log("API listening on port 3000");
});