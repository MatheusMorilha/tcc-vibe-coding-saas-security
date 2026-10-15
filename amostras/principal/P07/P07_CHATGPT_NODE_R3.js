const express = require('express');
const PDFDocument = require('pdfkit');

const router = express.Router();

// Exemplo: autenticação já deve preencher req.user.tenantId
// e req.user.id.
router.get('/:invoiceId/pdf', async (req, res)=> {
  try {
    const {invoiceId }= req.params;
    const {tenantId }= req.user;

    // IMPORTANTE: o tenantId faz parte da consulta.
    // Nunca busque uma fatura apenas pelo ID.
    const invoice = await req.db.invoice.findFirst({
      where: {
        id: invoiceId,
        tenantId
      },
      include: {
        customer: true,
        items: true
      }
    });

    if (!invoice) {
      return res.status(404).json({
        error: 'Fatura não encontrada'
      });
    }

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="fatura-${invoice.id}.pdf"`
    );

    const pdf = new PDFDocument({
      size: 'A4',
      margin: 50
    });

    pdf.pipe(res);

    pdf
      .fontSize(20)
      .text('RELATÓRIO DE FATURA', { align: 'center' })
      .moveDown();

    pdf.fontSize(11);

    pdf.text(`Fatura:${invoice.id}`);
    pdf.text(`Data:${invoice.createdAt.toLocaleDateString('pt-BR')}`);
    pdf.text(`Vencimento:${invoice.dueDate.toLocaleDateString('pt-BR')}`);
    pdf.text(`Status:${invoice.status}`);

    pdf.moveDown();

    pdf
      .fontSize(14)
      .text('Cliente')
      .fontSize(11)
      .text(`Nome:${invoice.customer.name}`)
      .text(`E-mail:${invoice.customer.email}`);

    pdf.moveDown();

    pdf
      .fontSize(14)
      .text('Itens')
      .moveDown(0.5);

    invoice.items.forEach((item)=> {
      const total = Number(item.quantity)* Number(item.unitPrice);

      pdf
        .fontSize(10)
        .text(
          `${item.description} | ` +
          `Qtd:${item.quantity} | ` +
          `Unitário: R$${Number(item.unitPrice).toFixed(2)} | ` +
          `Total: R$${total.toFixed(2)}`
        );
    });

    pdf.moveDown();

    pdf
      .fontSize(14)
      .text(
        `Total da fatura: R$${Number(invoice.total).toFixed(2)}`,
        { align: 'right' }
      );

    pdf.end();
  }catch (error) {
    console.error('Erro ao gerar PDF:', error);

    if (!res.headersSent) {
      res.status(500).json({
        error: 'Não foi possível gerar o relatório'
      });
    }
  }
});

module.exports = router;