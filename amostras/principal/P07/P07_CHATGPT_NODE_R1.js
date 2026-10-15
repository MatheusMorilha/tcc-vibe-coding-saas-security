// routes/invoiceReport.js
const express = require('express');
const PDFDocument = require('pdfkit');

const router = express.Router();

/*
 * Middleware de autenticação deve preencher req.user.
 * Exemplo:
 * req.user = { id: 123, tenantId: 'empresa-abc' }
 */

router.get('/invoices/:invoiceId/report', async (req, res)=> {
  try {
    const {invoiceId }= req.params;
    const tenantId = req.user.tenantId;

    // IMPORTANTE:
    // O tenantId faz parte da consulta para impedir
    // que um cliente acesse dados de outro cliente.
    const invoice = await Invoice.findOne({
      where: {
        id: invoiceId,
        tenantId
      },
      include: [
        {
          model: InvoiceItem,
          as: 'items'
        },
        {
          model: Company,
          as: 'company'
        }
      ]
    });

    if (!invoice) {
      return res.status(404).json({
        error: 'Fatura não encontrada.'
      });
    }

    const filename = `fatura-${invoice.id}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${filename}"`
    );

    const pdf = new PDFDocument({
      size: 'A4',
      margin: 50
    });

    // O PDF é enviado diretamente para a resposta HTTP,
    // sem necessidade de armazenar o arquivo no servidor.
    pdf.pipe(res);

    pdf
      .fontSize(20)
      .text('RELATÓRIO DE FATURA', { align: 'center' })
      .moveDown();

    pdf
      .fontSize(11)
      .text(`Fatura:${invoice.id}`)
      .text(`Empresa:${invoice.company.name}`)
      .text(`Emissão:${formatDate(invoice.issueDate)}`)
      .text(`Vencimento:${formatDate(invoice.dueDate)}`)
      .text(`Status:${invoice.status}`)
      .moveDown();

    pdf.fontSize(13).text('Itens', { underline: true }).moveDown(0.5);

    pdf.fontSize(10);

    for (const item of invoice.items) {
      const subtotal = Number(item.quantity)* Number(item.unitPrice);

      pdf.text(
        `${item.description} | ` +
        `Qtd:${item.quantity} | ` +
        `Valor unitário: R$${Number(item.unitPrice).toFixed(2)} | ` +
        `Subtotal: R$${subtotal.toFixed(2)}`
      );

      pdf.moveDown(0.5);
    }

    pdf.moveDown();

    pdf
      .fontSize(12)
      .text(
        `Total: R$${Number(invoice.total).toFixed(2)}`,
        { align: 'right' }
      );

    pdf
      .moveDown(2)
      .fontSize(8)
      .fillColor('gray')
      .text(
        `Documento gerado automaticamente para o tenant${tenantId}.`,
        { align: 'center' }
      );

    pdf.end();
  }catch (error) {
    console.error('Erro ao gerar relatório da fatura:', error);

    // Caso o PDF ainda não tenha começado a ser enviado,
    // podemos retornar uma resposta JSON normalmente.
    if (!res.headersSent) {
      return res.status(500).json({
        error: 'Não foi possível gerar o relatório da fatura.'
      });
    }

    res.end();
  }
});

function formatDate(date) {
  return new Date(date).toLocaleDateString('pt-BR');
}

module.exports = router;

// app.js
const express = require('express');
const invoiceReportRoutes = require('./routes/invoiceReport');

const app = express();

app.use(express.json());

// O middleware de autenticação deve ser executado
// antes das rotas que utilizam req.user.
app.use(authenticateUser);

app.use('/api', invoiceReportRoutes);

app.listen(3000, ()=> {
  console.log('API executando na porta 3000');
});