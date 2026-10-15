'use strict';

const express = require('express');
const PDFDocument = require('pdfkit');
const { Pool } = require('pg');

const router = express.Router();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const ROLES_ALLOWED = new Set(['owner', 'admin', 'finance']);

/**
 * Pressupõe um middleware de autenticação anterior (ex.: JWT/sessão) que
 * popula req.user = { id, tenantId, role } a partir de credenciais validadas
 * no servidor. O tenantId NUNCA deve vir de body, query ou params.
 */
function requireAuth(req, res, next) {
  if (!req.user || !req.user.tenantId) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  next();
}

function requireFinanceRole(req, res, next) {
  if (!ROLES_ALLOWED.has(req.user.role)) {
    return res.status(403).json({ error: 'Sem permissão para acessar faturas.' });
  }
  next();
}

const fmtMoney = (value, currency = 'BRL') =>
  new Intl.NumberFormat('pt-BR', { style: 'currency', currency }).format(
    Number(value)
  );

const fmtDate = (d) =>
  d ? new Date(d).toLocaleDateString('pt-BR', { timeZone: 'UTC' }) : '-';

/** Remove caracteres perigosos para uso em cabeçalhos HTTP / nomes de arquivo. */
const safeFilename = (s) => String(s).replace(/[^A-Za-z0-9_-]/g, '_');

async function loadInvoice(tenantId, invoiceId) {
  // Toda consulta filtra por tenant_id: impede acesso a faturas de outras empresas.
  const { rows } = await pool.query(
    `SELECT i.id, i.number, i.status, i.currency, i.issue_date, i.due_date,
            i.subtotal, i.discount, i.tax, i.total, i.notes,
            t.name  AS tenant_name,
            t.tax_id AS tenant_tax_id,
            c.name  AS customer_name,
            c.tax_id AS customer_tax_id,
            c.email AS customer_email
       FROM invoices i
       JOIN tenants   t ON t.id = i.tenant_id
       JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
      WHERE i.id = $1
        AND i.tenant_id = $2`,
    [invoiceId, tenantId]
  );
  if (rows.length === 0) return null;

  const { rows: items } = await pool.query(
    `SELECT description, quantity, unit_price, total
       FROM invoice_items
      WHERE invoice_id = $1
        AND tenant_id = $2
      ORDER BY position ASC`,
    [invoiceId, tenantId]
  );

  return { ...rows[0], items };
}

function buildPdf(inv) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4',
      margin: 50,
      info: { Title: `Fatura ${inv.number}`, Author: inv.tenant_name },
    });

    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // Cabeçalho
    doc.fontSize(20).font('Helvetica-Bold').text(inv.tenant_name);
    doc.fontSize(10).font('Helvetica').text(`CNPJ: ${inv.tenant_tax_id || '-'}`);
    doc.moveDown();
    doc.fontSize(16).font('Helvetica-Bold').text(`Fatura Nº ${inv.number}`);
    doc.fontSize(10).font('Helvetica');
    doc.text(`Status: ${inv.status}`);
    doc.text(`Emissão: ${fmtDate(inv.issue_date)}`);
    doc.text(`Vencimento: ${fmtDate(inv.due_date)}`);
    doc.moveDown();

    // Cliente
    doc.font('Helvetica-Bold').text('Cliente');
    doc.font('Helvetica');
    doc.text(inv.customer_name);
    doc.text(`CPF/CNPJ: ${inv.customer_tax_id || '-'}`);
    doc.text(`E-mail: ${inv.customer_email || '-'}`);
    doc.moveDown();

    // Tabela de itens
    const col = { desc: 50, qty: 320, unit: 380, total: 470 };
    let y = doc.y;
    doc.font('Helvetica-Bold');
    doc.text('Descrição', col.desc, y);
    doc.text('Qtd', col.qty, y);
    doc.text('Unitário', col.unit, y);
    doc.text('Total', col.total, y);
    y += 16;
    doc.moveTo(50, y).lineTo(545, y).stroke();
    y += 6;

    doc.font('Helvetica');
    for (const item of inv.items) {
      if (y > 740) {
        doc.addPage();
        y = 50;
      }
      doc.text(item.description, col.desc, y, { width: 260 });
      const rowHeight = Math.max(
        doc.heightOfString(item.description, { width: 260 }),
        14
      );
      doc.text(String(item.quantity), col.qty, y);
      doc.text(fmtMoney(item.unit_price, inv.currency), col.unit, y);
      doc.text(fmtMoney(item.total, inv.currency), col.total, y);
      y += rowHeight + 6;
    }

    // Totais
    if (y > 680) {
      doc.addPage();
      y = 50;
    }
    y += 10;
    doc.moveTo(300, y).lineTo(545, y).stroke();
    y += 8;
    const line = (label, value, bold = false) => {
      doc.font(bold ? 'Helvetica-Bold' : 'Helvetica');
      doc.text(label, 300, y);
      doc.text(fmtMoney(value, inv.currency), col.total, y);
      y += 16;
    };
    line('Subtotal', inv.subtotal);
    line('Desconto', inv.discount);
    line('Impostos', inv.tax);
    line('TOTAL', inv.total, true);

    if (inv.notes) {
      doc.font('Helvetica-Bold').text('Observações', 50, y + 10);
      doc.font('Helvetica').text(inv.notes, 50, doc.y, { width: 495 });
    }

    doc.end();
  });
}

router.get(
  '/invoices/:invoiceId/pdf',
  requireAuth,
  requireFinanceRole,
  async (req, res) => {
    const { invoiceId } = req.params;

    if (!UUID_RE.test(invoiceId)) {
      return res.status(400).json({ error: 'Identificador de fatura inválido.' });
    }

    try {
      const invoice = await loadInvoice(req.user.tenantId, invoiceId);

      // 404 tanto para "não existe" quanto para "pertence a outra empresa",
      // evitando revelar a existência de recursos de outros locatários.
      if (!invoice) {
        return res.status(404).json({ error: 'Fatura não encontrada.' });
      }

      const pdf = await buildPdf(invoice);

      res.set({
        'Content-Type': 'application/pdf',
        'Content-Length': pdf.length,
        'Content-Disposition': `attachment; filename="fatura-${safeFilename(
          invoice.number
        )}.pdf"`,
        'Cache-Control': 'private, no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      return res.status(200).send(pdf);
    } catch (err) {
      console.error('Falha ao gerar PDF da fatura', {
        invoiceId,
        tenantId: req.user.tenantId,
        error: err.message,
      });
      return res.status(500).json({ error: 'Erro ao gerar o relatório.' });
    }
  }
);

module.exports = router;

/* Registro no app principal:
 *
 *   const invoicesPdf = require('./routes/invoices.pdf');
 *   app.use('/api', authMiddleware, invoicesPdf);
 */