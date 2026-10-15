const express = require('express');
const crypto = require('crypto');
const app = express();

// IMPORTANTE: O webhook precisa do body em formato Raw (Buffer) para validar a assinatura HMAC.
// Aplique express.raw() apenas nesta rota específica ou configure o parser adequadamente.
app.post(
  '/api/v1/webhooks/payment-gateway',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    // 1. Validação da Assinatura HMAC (Segurança)
    const signature = req.headers['x-signature-token'];
    const secret = process.env.PAYMENT_GATEWAY_WEBHOOK_SECRET;

    if (!isValidSignature(req.body, signature, secret)) {
      console.error('[WEBHOOK ERROR] Assinatura inválida.');
      return res.status(401).json({ error: 'Assinatura inválida.' });
    }

    let payload;
    try {
      payload = JSON.parse(req.body.toString());
    } catch (err) {
      console.error('[WEBHOOK ERROR] JSON malformatado:', err.message);
      return res.status(400).json({ error: 'Payload inválido.' });
    }

    const { event_type, event_id, data } = payload;
    const { invoice_id, tenant_id, status: paymentStatus, paid_at } = data;

    // Responde rapidamente com 200 OK para evitar timeouts do gateway,
    // processando as verificações dentro de um bloco controlado.
    try {
      // 2. Proteção contra Processamento Duplicado (Idempotência)
      const isProcessed = await checkAndMarkEventAsProcessed(event_id);
      if (isProcessed) {
        console.log(`[WEBHOOK INFO] Evento ${event_id} já processado anteriormente.`);
        return res.status(200).json({ received: true, note: 'Evento duplicado ignorado.' });
      }

      // 3. Processamento dentro de Transação do Banco de Dados
      await executeDatabaseTransaction(async (dbClient) => {
        // Busca a fatura garantindo o isolamento multilocatário (tenant_id)
        const invoice = await dbClient.query(
          `SELECT id, status FROM invoices WHERE id = $1 AND tenant_id = $2 FOR UPDATE`,
          [invoice_id, tenant_id]
        );

        if (!invoice) {
          throw new Error(`Fatura ${invoice_id} não encontrada para o tenant ${tenant_id}`);
        }

        // 4. Mapeamento de Eventos e Atualização de Estado
        switch (event_type) {
          case 'invoice.payment_succeeded':
            await dbClient.query(
              `UPDATE invoices
               SET status = 'PAID', paid_at = $1, updated_at = NOW()
               WHERE id = $2 AND tenant_id = $3`,
              [paid_at || new Date(), invoice_id, tenant_id]
            );

            // Renova o acesso do cliente/tenant
            await dbClient.query(
              `UPDATE subscriptions
               SET status = 'ACTIVE', current_period_end = NOW() + INTERVAL '1 month', updated_at = NOW()
               WHERE tenant_id = $1`,
              [tenant_id]
            );
            break;

          case 'invoice.payment_failed':
            await dbClient.query(
              `UPDATE invoices
               SET status = 'FAILED', updated_at = NOW()
               WHERE id = $1 AND tenant_id = $2`,
              [invoice_id, tenant_id]
            );

            // Atualiza a assinatura para inadimplente/inativa
            await dbClient.query(
              `UPDATE subscriptions
               SET status = 'PAST_DUE', updated_at = NOW()
               WHERE tenant_id = $1`,
              [tenant_id]
            );
            break;

          case 'invoice.refunded':
            await dbClient.query(
              `UPDATE invoices
               SET status = 'REFUNDED', updated_at = NOW()
               WHERE id = $1 AND tenant_id = $2`,
              [invoice_id, tenant_id]
            );
            break;

          default:
            console.log(`[WEBHOOK INFO] Evento ${event_type} não tratado.`);
        }
      });

      return res.status(200).json({ received: true });
    } catch (error) {
      console.error(`[WEBHOOK PROCESSING ERROR] Evento ${event_id}:`, error.message);
      // Retorna 500 para que o gateway de pagamento faça retentativas automáticas (retry logic)
      return res.status(500).json({ error: 'Erro interno ao processar notificação.' });
    }
  }
);

// Auxiliar: Validação HMAC SHA-256 da assinatura
function isValidSignature(rawBody, signature, secret){
  if (!signature || !secret) return false;

  const hmac = crypto.createHmac('sha256', secret);
  const digest = Buffer.from(hmac.update(rawBody).digest('hex'), 'utf8');
  const checksum = Buffer.from(signature, 'utf8');

  if (checksum.length !== digest.length) return false;
  return crypto.timingSafeEqual(digest, checksum);
}

// Auxiliar: Checagem de Idempotência (Exemplo com Redis ou Tabela de Audit)
async function checkAndMarkEventAsProcessed(eventId){
  // Exemplo em pseudocódigo usando chave única com expiração de 7 dias
  // const added = await redis.set(`webhook_event:${eventId}`, '1', 'NX', 'EX', 604800);
  // return added === null;
  return false;
}

// Auxiliar: Transação no Banco
async function executeDatabaseTransaction(callback){
  // Implementação padrão de transação (ex: pg, Prisma, Knex)
  // const client = await pool.connect();
  // try { await client.query('BEGIN'); await callback(client); await client.query('COMMIT'); }
  // catch(e) { await client.query('ROLLBACK'); throw e; }
  // finally { client.release(); }
}