'use strict';

const express = require('express');
const PDFDocument = require('pdfkit');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Papéis autorizados a emitir o relatório (ajuste conforme o RBAC do projeto)
const ALLOWED_ROLES = new Set(['owner', 'admin', 'finance']);

/**
 * Assume que um middleware de autenticação anterior (JWT/sessão) já validou
 * o token e preencheu req.user = { id, tenantId, role }.
 * O tenantId vem SEMPRE da sessão, nunca de body/query/params.
 */
function requireAuth(req, res, next) {
  const u = req.user;
  if (!u || !u.id || !u.tenantId) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  next();
}

function requireFinanceRole(req, res, next) {
  if (!ALLOWED_ROLES.has(req.user.role)) {
    return res.status(403).json({ error: 'Sem permissão para esta ação.' });
  }
  next();
}

// ---------- Acesso a dados (sempre filtrado por tenant) ----------

async function getInvoiceWithItems(tenantId, invoiceId) {
  const invoiceRes = await pool.query(
    `SELECT i.id, i.number, i.status, i.currency, i.issue_date, i.due_date,
            i.customer_name, i.customer_document, i.notes, i.total,
            t.name AS company_name
       FROM invoices i
       JOIN tenants t ON t.id = i.tenant_id
      WHERE i.id = $1
        AND i.tenant_id = $2`,
    [invoiceId, tenantId]
  );
  if (invoiceRes.rowCount === 0) return null;

  const itemsRes = await pool.query(
    `SELECT description, quantity, unit_price
       FROM invoice_items
      WHERE invoice_id = $1
        AND tenant_id = $2
      ORDER BY position ASC`,
    [invoiceId, tenantId]
  );

  return { ...invoiceRes.rows[0], items: itemsRes.rows };
}

async function logAudit(tenantId, userId, action, resourceId, ip) {
  try {
    await pool.query(
      `INSERT INTO audit_logs (tenant_id, user_id, action, resource_id, ip, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())`,
      [tenantId, userId, action, resourceId, ip]
    );
  } catch (err) {
    // Falha de auditoria não deve impedir o download, mas deve ser registrada
    console.error('Falha ao gravar auditoria:', err.message);
  }
}

// ---------- Geração do PDF ----------

const money = (value, currency) =>
  new Intl.NumberFormat('pt-BR', { style: 'currency', currency: currency || 'BRL' })
    .format(Number(value));

const dateBR = (d) => (d ? new Date(d).toLocaleDateString('pt-BR', { timeZone: 'UTC' }) : '-');

function buildInvoicePdf(invoice) {
  const doc = new PDFDocument({
    size: 'A4',
    margin: 50,
    info: { Title: `Fatura ${invoice.number}`, Author: invoice.company_name },
  });

  // Cabeçalho
  doc.fontSize(20).text(invoice.company_name, { align: 'left' });
  doc.moveDown(0.3).fontSize(14).text(`Fatura Nº ${invoice.number}`);
  doc.moveDown(0.3).fontSize(10).fillColor('#555')
    .text(`Status: ${invoice.status}`)
    .text(`Emissão: ${dateBR(invoice.issue_date)}`)
    .text(`Vencimento: ${dateBR(invoice.due_date)}`);
  doc.fillColor('#000');

  // Cliente
  doc.moveDown().fontSize(12).text('Cliente', { underline: true });
  doc.fontSize(10)
    .text(invoice.customer_name)
    .text(`Documento: ${invoice.customer_document || '-'}`);

  // Tabela de itens
  doc.moveDown();
  const colX = { desc: 50, qty: 320, unit: 380, total: 470 };
  let y = doc.y;

  doc.fontSize(10).font('Helvetica-Bold');
  doc.text('Descrição', colX.desc, y);
  doc.text('Qtd', colX.qty, y);
  doc.text('Unitário', colX.unit, y);
  doc.text('Total', colX.total, y);
  doc.font('Helvetica');
  y += 16;
  doc.moveTo(50, y).lineTo(545, y).stroke();
  y += 6;

  for (const item of invoice.items) {
    if (y > 740) {
      doc.addPage();
      y = 50;
    }
    const lineTotal = Number(item.quantity) * Number(item.unit_price);
    const startY = y;
    doc.text(item.description, colX.desc, y, { width: 260 });
    const descBottom = doc.y;
    doc.text(String(item.quantity), colX.qty, startY);
    doc.text(money(item.unit_price, invoice.currency), colX.unit, startY, { width: 85 });
    doc.text(money(lineTotal, invoice.currency), colX.total, startY, { width: 75 });
    y = Math.max(descBottom, startY + 14) + 6;
  }

  doc.moveTo(50, y).lineTo(545, y).stroke();
  y += 10;
  doc.font('Helvetica-Bold').fontSize(12)
    .text(`Total: ${money(invoice.total, invoice.currency)}`, 50, y, { align: 'right', width: 495 });
  doc.font('Helvetica');

  if (invoice.notes) {
    doc.moveDown(2).fontSize(10).text('Observações', 50, undefined, { underline: true });
    doc.text(invoice.notes, { width: 495 });
  }

  return doc;
}

// ---------- Rota ----------

// GET /api/invoices/:invoiceId/report.pdf
router.get(
  '/api/invoices/:invoiceId/report.pdf',
  requireAuth,
  requireFinanceRole,
  async (req, res) => {
    const { invoiceId } = req.params;
    const { id: userId, tenantId } = req.user;

    if (!UUID_RE.test(invoiceId)) {
      return res.status(400).json({ error: 'Identificador de fatura inválido.' });
    }

    try {
      const invoice = await getInvoiceWithItems(tenantId, invoiceId);

      // 404 (e não 403) para não revelar a existência de faturas de outros tenants
      if (!invoice) {
        return res.status(404).json({ error: 'Fatura não encontrada.' });
      }

      const safeNumber = String(invoice.number).replace(/[^A-Za-z0-9_-]/g, '');
      const filename = `fatura-${safeNumber || 'documento'}.pdf`;

      res.status(200);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Cache-Control', 'private, no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');

      const doc = buildInvoicePdf(invoice);

      doc.on('error', (err) => {
        console.error('Erro ao gerar PDF:', err.message);
        res.destroy(err);
      });
      res.on('close', () => {
        if (!doc._ended) doc.end();
      });

      doc.pipe(res);
      doc.end();

      // Auditoria do acesso ao documento
      logAudit(tenantId, userId, 'INVOICE_PDF_DOWNLOAD', invoiceId, req.ip);
    } catch (err) {
      console.error('Erro no relatório de fatura:', err);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Erro interno ao gerar o relatório.' });
      }
    }
  }
);

module.exports = router;