const express = require('express');
const PDFDocument = require('pdfkit');
const router = express.Router();

const Invoice = require('../models/Invoice');

// GET /api/invoices/:id/pdf
router.get('/:id/pdf', async (req, res)=> {
  try {
    const {id }= req.params;
    const tenantId = req.user.tenantId;

    // Importante: a fatura só pode ser buscada dentro do tenant autenticado.
    const invoice = await Invoice.findOne({
      _id: id,
      tenantId
    }).lean();

    if (!invoice) {
      return res.status(404).json({
        error: 'Fatura não encontrada.'
      });
    }

    const filename = `fatura-${invoice.number|| invoice._id}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${filename}"`
    );

    const doc = new PDFDocument({
      size: 'A4',
      margin: 50
    });

    doc.pipe(res);

    doc.fontSize(20)
      .text('RELATÓRIO DE FATURA', { align: 'center' });

    doc.moveDown();

    doc.fontSize(12)
      .text(`Número:${invoice.number}`)
      .text(`Data de emissão:${formatDate(invoice.issueDate)}`)
      .text(`Vencimento:${formatDate(invoice.dueDate)}`)
      .text(`Status:${invoice.status}`);

    doc.moveDown();

    doc.fontSize(14).text('Cliente');
    doc.fontSize(12)
      .text(`Nome:${invoice.customer.name}`)
      .text(`Documento:${invoice.customer.document}`)
      .text(`E-mail:${invoice.customer.email}`);

    doc.moveDown();

    doc.fontSize(14).text('Itens');

    doc.moveDown(0.5);

    invoice.items.forEach((item, index)=> {
      const subtotal = item.quantity* item.unitPrice;

      doc.fontSize(11).text(
        `${index+ 1}.${item.description}`
      );

      doc.text(
        `Quantidade:${item.quantity} | ` +
        `Valor unitário:${formatCurrency(item.unitPrice)} | ` +
        `Subtotal:${formatCurrency(subtotal)}`
      );

      doc.moveDown(0.5);
    });

    doc.moveDown();

    doc.fontSize(14)
      .text(`Subtotal:${formatCurrency(invoice.subtotal)}`)
      .text(`Impostos:${formatCurrency(invoice.taxes)}`)
      .text(`Desconto:${formatCurrency(invoice.discount)}`)
      .text(`Total:${formatCurrency(invoice.total)}`);

    doc.moveDown(2);

    doc.fontSize(9)
      .fillColor('gray')
      .text(
        'Documento gerado automaticamente pela plataforma.',
        { align: 'center' }
      );

    doc.end();
  }catch (error) {
    console.error('Erro ao gerar PDF da fatura:', error);

    if (!res.headersSent) {
      return res.status(500).json({
        error: 'Não foi possível gerar o relatório.'
      });
    }

    res.end();
  }
});

function formatCurrency(value) {
  return new Intl.NumberFormat('pt-BR', {
    style: 'currency',
    currency: 'BRL'
  }).format(Number(value|| 0));
}

function formatDate(value) {
  if (!value)return '-';

  return new Intl.DateTimeFormat('pt-BR').format(
    new Date(value)
  );
}

module.exports = router;

const express = require('express');
const invoiceRoutes = require('./routes/invoices');

const app = express();

app.use('/api/invoices', invoiceRoutes);