// invoice-pdf.route.js
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import PDFDocument from 'pdfkit';
import { z } from 'zod';
import { pool } from '../db.js';                          // pg.Pool (conexão com TLS em produção)
import { authenticate, requirePermission } from '../auth.js'; // JWT/sessão -> req.user = { id, tenantId, permissions }
import { logger } from '../logger.js';                    // logger estruturado (sem dados sensíveis)

const router = Router();

// A04: limita abuso/DoS, já que gerar PDF é uma operação custosa
const pdfLimiter = rateLimit({
  windowMs: 60_000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.user?.tenantId}:${req.user?.id}`,
});

// A03: valida o formato do parâmetro antes de tocar no banco
const paramsSchema = z.object({ invoiceId: z.string().uuid() });

const MAX_ITEMS = 500;
const ISO_CURRENCY = /^[A-Z]{3}$/;

// Remove caracteres de controle de textos vindos do banco
const clean = (v, max = 200) =>
  String(v ?? '').replace(/[\u0000-\u001F\u007F]/g, ' ').slice(0, max);

const money = (cents, currency) =>
  new Intl.NumberFormat('pt-BR', {
    style: 'currency',
    currency: ISO_CURRENCY.test(currency) ? currency : 'BRL',
  }).format(Number(cents) / 100);

const fmtDate = (d) => (d ? new Date(d).toLocaleDateString('pt-BR', { timeZone: 'UTC' }) : '-');

function buildPdf(inv, items) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4',
      margin: 50,
      info: { Title: `Fatura ${clean(inv.number, 40)}`, Producer: 'SaaS Invoice Service' },
    });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // Cabeçalho
    doc.fontSize(20).text(clean(inv.tenant_name), { align: 'left' });
    doc.moveDown(0.5).fontSize(16).text(`Fatura Nº ${clean(inv.number, 40)}`);
    doc.fontSize(10).fillColor('#555')
      .text(`Emissão: ${fmtDate(inv.issue_date)}   Vencimento: ${fmtDate(inv.due_date)}   Status: ${clean(inv.status, 20)}`)
      .fillColor('#000').moveDown();

    // Cliente
    doc.fontSize(12).text('Cliente', { underline: true });
    doc.fontSize(10)
      .text(clean(inv.customer_name))
      .text(`Documento: ${clean(inv.customer_document, 30)}`)
      .moveDown();

    // Itens
    const col = { desc: 50, qty: 330, unit: 390, total: 470 };
    let y = doc.y;
    doc.fontSize(10).font('Helvetica-Bold');
    doc.text('Descrição', col.desc, y).text('Qtd', col.qty, y)
      .text('Unitário', col.unit, y).text('Total', col.total, y);
    doc.font('Helvetica').moveTo(50, y + 14).lineTo(545, y + 14).stroke();
    y += 22;

    for (const it of items) {
      if (y > 740) { doc.addPage(); y = 50; }
      const lineTotal = BigInt(it.unit_price_cents) * BigInt(Math.round(Number(it.quantity) * 1000)) / 1000n;
      doc.text(clean(it.description, 120), col.desc, y, { width: 270 })
        .text(String(it.quantity), col.qty, y)
        .text(money(it.unit_price_cents, inv.currency), col.unit, y)
        .text(money(lineTotal, inv.currency), col.total, y);
      y += 20;
    }

    doc.font('Helvetica-Bold').fontSize(12)
      .text(`Total: ${money(inv.total_cents, inv.currency)}`, 50, y + 15, { align: 'right', width: 495 });

    doc.end();
  });
}

// GET /api/v1/invoices/:invoiceId/pdf
router.get(
  '/:invoiceId/pdf',
  authenticate,                       // A07: exige identidade válida
  requirePermission('invoice:read'),  // A01: controle de acesso por papel/permissão
  pdfLimiter,
  async (req, res) => {
    const parsed = paramsSchema.safeParse(req.params);
    if (!parsed.success) return res.status(400).json({ error: 'Identificador inválido.' });

    const { invoiceId } = parsed.data;
    const { tenantId, id: userId } = req.user; // A01: tenant vem do token, NUNCA da requisição

    try {
      // A01/A03: consulta parametrizada + filtro obrigatório por tenant (anti-IDOR)
      const invRes = await pool.query(
        `SELECT i.id, i.number, i.issue_date, i.due_date, i.status, i.currency, i.total_cents,
                c.name AS customer_name, c.document AS customer_document,
                t.name AS tenant_name
           FROM invoices i
           JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
           JOIN tenants   t ON t.id = i.tenant_id
          WHERE i.id = $1 AND i.tenant_id = $2`,
        [invoiceId, tenantId]
      );

      // Mesma resposta para "não existe" e "pertence a outro tenant" (evita enumeração)
      if (invRes.rowCount === 0) return res.status(404).json({ error: 'Fatura não encontrada.' });
      const invoice = invRes.rows[0];

      const itemsRes = await pool.query(
        `SELECT description, quantity, unit_price_cents
           FROM invoice_items
          WHERE invoice_id = $1 AND tenant_id = $2
          ORDER BY position
          LIMIT $3`,
        [invoiceId, tenantId, MAX_ITEMS]
      );

      // Gera em memória: se falhar, nenhum PDF parcial é enviado
      const pdf = await buildPdf(invoice, itemsRes.rows);

      // A09: trilha de auditoria sem dados pessoais do cliente
      logger.info({ event: 'invoice.pdf.download', tenantId, userId, invoiceId });

      const safeName = `fatura-${String(invoice.number).replace(/[^A-Za-z0-9_-]/g, '')}.pdf`;
      res.set({
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="${safeName}"`,
        'Content-Length': pdf.length,
        'Cache-Control': 'private, no-store',   // A02: dados financeiros não ficam em cache
        'X-Content-Type-Options': 'nosniff',
      });
      return res.status(200).send(pdf);
    } catch (err) {
      // A05/A09: registra o detalhe internamente, devolve mensagem genérica
      logger.error({ event: 'invoice.pdf.error', tenantId, userId, invoiceId, msg: err.message });
      return res.status(500).json({ error: 'Não foi possível gerar o relatório.' });
    }
  }
);

export default router;

/* ---- Registro no app (app.js) ----
import express from 'express';
import helmet from 'helmet';
import invoicePdfRouter from './routes/invoice-pdf.route.js';

const app = express();
app.disable('x-powered-by');
app.use(helmet());                       // A05: cabeçalhos de segurança
app.use('/api/v1/invoices', invoicePdfRouter);
*/