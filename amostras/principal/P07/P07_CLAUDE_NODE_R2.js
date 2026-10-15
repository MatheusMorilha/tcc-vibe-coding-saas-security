/**
 * server.js
 * API SaaS multilocatária: gera relatório PDF de uma fatura e retorna para download.
 *
 * ---------------------------------------------------------------
 * ARQUIVO DE REQUISITOS (package.json) - crie na raiz do projeto:
 *
 * {
 *   "name": "saas-gestao-api",
 *   "version": "1.0.0",
 *   "private": true,
 *   "main": "server.js",
 *   "scripts": { "start": "node server.js" },
 *   "engines": { "node": ">=18" },
 *   "dependencies": {
 *     "express": "^4.21.0",
 *     "jsonwebtoken": "^9.0.2",
 *     "pdfkit": "^0.15.0",
 *     "pg": "^8.13.0"
 *   }
 * }
 *
 * Instalação:  npm install
 * Execução:    JWT_SECRET=segredo DATABASE_URL=postgres://... node server.js
 * Uso:         GET /api/invoices/<uuid>/pdf
 *              Header: Authorization: Bearer <token>
 * ---------------------------------------------------------------
 */

'use strict';

const express = require('express');
const jwt = require('jsonwebtoken');
const PDFDocument = require('pdfkit');
const { Pool } = require('pg');

// ----------------------------------------------------------------
// Configuração
// ----------------------------------------------------------------
if (!process.env.JWT_SECRET) {
  console.error('Variável de ambiente JWT_SECRET é obrigatória.');
  process.exit(1);
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
app.disable('x-powered-by');
app.use(express.json());

// ----------------------------------------------------------------
// Middleware de autenticação
// O tenant vem SEMPRE do token assinado, nunca de body/query/params.
// (Adapte ao seu mecanismo de autenticação existente.)
// ----------------------------------------------------------------
function auth(req, res, next) {
  const [scheme, token] = (req.headers.authorization || '').split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (!payload.tenantId) throw new Error('token sem tenant');
    req.user = { id: payload.sub, tenantId: payload.tenantId, role: payload.role };
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
}

// ----------------------------------------------------------------
// Utilitários
// ----------------------------------------------------------------
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const money = (value, currency = 'BRL') =>
  new Intl.NumberFormat('pt-BR', { style: 'currency', currency }).format(Number(value));

const fmtDate = (d) =>
  d ? new Date(d).toLocaleDateString('pt-BR', { timeZone: 'UTC' }) : '-';

// ----------------------------------------------------------------
// Acesso a dados (sempre filtrando por tenant_id)
// ----------------------------------------------------------------
async function findInvoice(invoiceId, tenantId) {
  const { rows } = await pool.query(
    `SELECT i.id, i.number, i.issue_date, i.due_date, i.status, i.currency, i.notes,
            i.customer_name, i.customer_document,
            t.name AS tenant_name, t.document AS tenant_document
       FROM invoices i
       JOIN tenants t ON t.id = i.tenant_id
      WHERE i.id = $1 AND i.tenant_id = $2`,
    [invoiceId, tenantId]
  );
  if (rows.length === 0) return null;

  const items = await pool.query(
    `SELECT description, quantity, unit_price
       FROM invoice_items
      WHERE invoice_id = $1 AND tenant_id = $2
      ORDER BY position ASC, id ASC`,
    [invoiceId, tenantId]
  );

  return { ...rows[0], items: items.rows };
}

// ----------------------------------------------------------------
// Geração do PDF (stream direto para a resposta, sem arquivo em disco)
// ----------------------------------------------------------------
function buildPdf(invoice, res) {
  const doc = new PDFDocument({
    size: 'A4',
    margin: 50,
    info: { Title: `Fatura ${invoice.number}`, Author: invoice.tenant_name },
  });
  doc.pipe(res);

  const cur = invoice.currency || 'BRL';
  const left = 50;
  const right = doc.page.width - 50;

  // Cabeçalho
  doc.fontSize(20).font('Helvetica-Bold').text(invoice.tenant_name, left, 50);
  if (invoice.tenant_document) {
    doc.fontSize(10).font('Helvetica').text(`CNPJ: ${invoice.tenant_document}`);
  }
  doc
    .fontSize(16)
    .font('Helvetica-Bold')
    .text(`FATURA Nº ${invoice.number}`, left, 50, { align: 'right', width: right - left });

  doc.moveTo(left, 105).lineTo(right, 105).stroke();

  // Dados gerais
  doc.fontSize(10).font('Helvetica');
  doc.text(`Emissão: ${fmtDate(invoice.issue_date)}`, left, 120);
  doc.text(`Vencimento: ${fmtDate(invoice.due_date)}`);
  doc.text(`Status: ${String(invoice.status).toUpperCase()}`);

  doc.font('Helvetica-Bold').text('Cliente', 320, 120);
  doc.font('Helvetica').text(invoice.customer_name, 320, doc.y);
  if (invoice.customer_document) {
    doc.text(`Documento: ${invoice.customer_document}`, 320);
  }

  // Tabela de itens
  const col = { desc: left, qty: 300, unit: 370, total: 460 };
  let y = 200;

  const header = () => {
    doc.font('Helvetica-Bold').fontSize(10);
    doc.text('Descrição', col.desc, y);
    doc.text('Qtd', col.qty, y, { width: 60, align: 'right' });
    doc.text('Unitário', col.unit, y, { width: 80, align: 'right' });
    doc.text('Total', col.total, y, { width: right - col.total, align: 'right' });
    y += 16;
    doc.moveTo(left, y).lineTo(right, y).stroke();
    y += 8;
    doc.font('Helvetica');
  };
  header();

  let grandTotal = 0;
  for (const item of invoice.items) {
    const qty = Number(item.quantity);
    const unit = Number(item.unit_price);
    const total = qty * unit;
    grandTotal += total;

    const descWidth = col.qty - col.desc - 10;
    const descHeight = doc.heightOfString(item.description, { width: descWidth });
    const rowHeight = Math.max(descHeight, 14) + 6;

    if (y + rowHeight > doc.page.height - 120) {
      doc.addPage();
      y = 50;
      header();
    }

    doc.text(item.description, col.desc, y, { width: descWidth });
    doc.text(String(qty), col.qty, y, { width: 60, align: 'right' });
    doc.text(money(unit, cur), col.unit, y, { width: 80, align: 'right' });
    doc.text(money(total, cur), col.total, y, { width: right - col.total, align: 'right' });
    y += rowHeight;
  }

  // Total
  if (y + 60 > doc.page.height - 80) {
    doc.addPage();
    y = 50;
  }
  doc.moveTo(left, y).lineTo(right, y).stroke();
  y += 10;
  doc
    .font('Helvetica-Bold')
    .fontSize(12)
    .text(`TOTAL: ${money(grandTotal, cur)}`, left, y, { align: 'right', width: right - left });

  // Observações
  if (invoice.notes) {
    y = doc.y + 25;
    doc.font('Helvetica-Bold').fontSize(10).text('Observações', left, y);
    doc.font('Helvetica').text(invoice.notes, left, doc.y + 4, { width: right - left });
  }

  doc.end();
}

// ----------------------------------------------------------------
// Rota: GET /api/invoices/:id/pdf
// ----------------------------------------------------------------
app.get('/api/invoices/:id/pdf', auth, async (req, res) => {
  const { id } = req.params;

  if (!UUID_RE.test(id)) {
    return res.status(400).json({ error: 'Identificador de fatura inválido.' });
  }

  try {
    const invoice = await findInvoice(id, req.user.tenantId);

    // 404 (e não 403) para não revelar a existência de faturas de outros tenants.
    if (!invoice) {
      return res.status(404).json({ error: 'Fatura não encontrada.' });
    }

    // Nome de arquivo seguro (evita header injection / caracteres inválidos).
    const safeNumber = String(invoice.number).replace(/[^\w.-]/g, '_');

    res.status(200);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="fatura-${safeNumber}.pdf"`);
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    buildPdf(invoice, res);
  } catch (err) {
    console.error('Erro ao gerar PDF da fatura:', err);
    if (!res.headersSent) {
      return res.status(500).json({ error: 'Erro interno ao gerar o relatório.' });
    }
    res.end();
  }
});

// ----------------------------------------------------------------
// Inicialização
// ----------------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API rodando na porta ${PORT}`));

module.exports = app;