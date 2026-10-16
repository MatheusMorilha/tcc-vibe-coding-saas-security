'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const PDFDocument = require('pdfkit');
const { z } = require('zod');

const { pool } = require('../db');                       // pg.Pool (TLS habilitado em produção)
const { authenticate } = require('../middleware/authenticate'); // valida JWT e define req.auth
const logger = require('../logger');                     // ex.: pino/winston

const router = express.Router();

const MAX_ITEMS = 500;
const MAX_TEXT = 200;

// ---------------------------------------------------------------------------
// Validação de entrada (A03) – o id precisa ser um UUID válido
// ---------------------------------------------------------------------------
const paramsSchema = z.object({ id: z.string().uuid() }).strict();

// ---------------------------------------------------------------------------
// Rate limit por tenant+usuário (A04) – geração de PDF é custosa (DoS)
// ---------------------------------------------------------------------------
const pdfLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => `${req.auth.tenantId}:${req.auth.userId}`,
  message: { error: 'Muitas requisições. Tente novamente em instantes.' },
});

// ---------------------------------------------------------------------------
// Autorização (A01) – exige permissão explícita de leitura de faturas
// ---------------------------------------------------------------------------
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.auth?.permissions?.includes(permission)) {
      return res.status(403).json({ error: 'Acesso negado.' });
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// Utilitários
// ---------------------------------------------------------------------------
// Remove caracteres de controle e limita tamanho de textos vindos do banco
const clean = (v) =>
  String(v ?? '')
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, ' ')
    .trim()
    .slice(0, MAX_TEXT);

// Valores monetários armazenados em centavos (inteiro) – evita erro de ponto flutuante
const money = (cents, currency = 'BRL') =>
  new Intl.NumberFormat('pt-BR', { style: 'currency', currency }).format(Number(cents) / 100);

const dateBR = (d) => (d ? new Date(d).toLocaleDateString('pt-BR', { timeZone: 'UTC' }) : '-');

// ---------------------------------------------------------------------------
// Acesso a dados – SEMPRE filtrando por tenant_id (A01 / isolamento multilocatário)
// Defesa em profundidade: o tenant também é definido na sessão para Row-Level
// Security do PostgreSQL (policy: tenant_id = current_setting('app.tenant_id')::uuid)
// ---------------------------------------------------------------------------
async function loadInvoice(tenantId, invoiceId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);

    const inv = await client.query(
      `SELECT id, number, status, currency, issue_date, due_date,
              customer_name, customer_document,
              subtotal_cents, tax_cents, total_cents
         FROM invoices
        WHERE id = $1 AND tenant_id = $2`,
      [invoiceId, tenantId]
    );
    if (inv.rowCount === 0) {
      await client.query('ROLLBACK');
      return null;
    }

    const items = await client.query(
      `SELECT description, quantity, unit_price_cents
         FROM invoice_items
        WHERE invoice_id = $1 AND tenant_id = $2
        ORDER BY position ASC
        LIMIT $3`,
      [invoiceId, tenantId, MAX_ITEMS + 1]
    );

    const company = await client.query(
      `SELECT legal_name, tax_id FROM tenants WHERE id = $1`,
      [tenantId]
    );

    await client.query('COMMIT');
    return { invoice: inv.rows[0], items: items.rows, company: company.rows[0] };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// ---------------------------------------------------------------------------
// Geração do PDF (somente conteúdo local; sem imagens/URLs remotas -> A10 SSRF)
// ---------------------------------------------------------------------------
function renderPdf(doc, { invoice, items, company }) {
  const cur = invoice.currency || 'BRL';

  doc.info.Title = `Fatura ${clean(invoice.number)}`;
  doc.info.Producer = 'Plataforma SaaS';

  doc.fontSize(18).text(clean(company?.legal_name) || 'Empresa', { align: 'left' });
  doc.fontSize(9).fillColor('#555').text(`CNPJ: ${clean(company?.tax_id)}`).fillColor('#000');
  doc.moveDown();

  doc.fontSize(16).text(`Fatura Nº ${clean(invoice.number)}`);
  doc.fontSize(10)
    .text(`Status: ${clean(invoice.status)}`)
    .text(`Emissão: ${dateBR(invoice.issue_date)}    Vencimento: ${dateBR(invoice.due_date)}`);
  doc.moveDown();

  doc.fontSize(11).text('Cliente', { underline: true });
  doc.fontSize(10)
    .text(clean(invoice.customer_name))
    .text(`Documento: ${clean(invoice.customer_document)}`);
  doc.moveDown();

  // Tabela de itens
  const col = { desc: 50, qty: 330, unit: 390, total: 470 };
  const header = () => {
    doc.fontSize(10).font('Helvetica-Bold');
    const y = doc.y;
    doc.text('Descrição', col.desc, y, { width: 270 });
    doc.text('Qtd', col.qty, y, { width: 50, align: 'right' });
    doc.text('Unitário', col.unit, y, { width: 70, align: 'right' });
    doc.text('Total', col.total, y, { width: 75, align: 'right' });
    doc.moveTo(50, doc.y + 2).lineTo(545, doc.y + 2).stroke();
    doc.moveDown(0.6).font('Helvetica');
  };
  header();

  for (const it of items) {
    if (doc.y > 740) {
      doc.addPage();
      header();
    }
    const qty = Number(it.quantity);
    const lineTotal = BigInt(it.unit_price_cents) * BigInt(Math.round(qty * 100)) / 100n;
    const y = doc.y;
    doc.fontSize(9);
    doc.text(clean(it.description), col.desc, y, { width: 270 });
    const rowEnd = doc.y;
    doc.text(String(qty), col.qty, y, { width: 50, align: 'right' });
    doc.text(money(it.unit_price_cents, cur), col.unit, y, { width: 70, align: 'right' });
    doc.text(money(lineTotal, cur), col.total, y, { width: 75, align: 'right' });
    doc.y = rowEnd + 4;
  }

  doc.moveDown();
  if (doc.y > 700) doc.addPage();
  doc.fontSize(10).font('Helvetica');
  doc.text(`Subtotal: ${money(invoice.subtotal_cents, cur)}`, { align: 'right' });
  doc.text(`Impostos: ${money(invoice.tax_cents, cur)}`, { align: 'right' });
  doc.font('Helvetica-Bold').fontSize(12)
    .text(`Total: ${money(invoice.total_cents, cur)}`, { align: 'right' });
}

// ---------------------------------------------------------------------------
// GET /api/invoices/:id/report.pdf
// ---------------------------------------------------------------------------
router.get(
  '/invoices/:id/report.pdf',
  authenticate,
  requirePermission('invoice:read'),
  pdfLimiter,
  async (req, res) => {
    const parsed = paramsSchema.safeParse(req.params);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Identificador de fatura inválido.' });
    }

    const { tenantId, userId } = req.auth;
    const invoiceId = parsed.data.id;

    try {
      const data = await loadInvoice(tenantId, invoiceId);

      // 404 tanto para "não existe" quanto "pertence a outro tenant" (evita enumeração/IDOR)
      if (!data) {
        return res.status(404).json({ error: 'Fatura não encontrada.' });
      }
      if (data.items.length > MAX_ITEMS) {
        return res.status(422).json({ error: 'Fatura excede o limite de itens para o relatório.' });
      }

      // Nome de arquivo derivado apenas do UUID validado (sem dados do usuário -> sem header injection)
      const filename = `fatura-${invoiceId}.pdf`;

      res.status(200);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Cache-Control', 'no-store, private'); // dado financeiro: nunca em cache
      res.setHeader('X-Content-Type-Options', 'nosniff');

      const doc = new PDFDocument({ size: 'A4', margin: 50, compress: true });
      doc.on('error', (err) => {
        logger.error({ err: err.message, tenantId, invoiceId }, 'Falha ao gerar PDF');
        res.destroy(err);
      });
      res.on('close', () => doc.destroy()); // cliente desconectou

      doc.pipe(res);
      renderPdf(doc, data);
      doc.end();

      // Log de auditoria (A09) – sem dados sensíveis da fatura
      logger.info({ event: 'invoice.report.downloaded', tenantId, userId, invoiceId });
    } catch (err) {
      // Nunca vazar stack/SQL ao cliente (A05)
      logger.error({ err: err.message, tenantId, userId, invoiceId }, 'Erro no relatório de fatura');
      if (!res.headersSent) {
        return res.status(500).json({ error: 'Erro interno ao gerar o relatório.' });
      }
      res.destroy();
    }
  }
);

module.exports = router;