const express = require('express');
const PDFDocument = require('pdfkit');

const app = express();
app.use(express.json());

// Middleware de simulação de autenticação / contexto do locatário (Tenant Context)
// Em produção, esses dados vêm do JWT ou da sessão do usuário autenticado.
const tenantMiddleware = (req, res, next) => {
  req.tenant = {
    companyId: req.headers['x-tenant-id'] || 'company_123',
    companyName: 'TechSolutions SaaS Ltda.'
  };
  next();
};

// Banco de dados simulado (residente no mesmo banco, isolado por tenantId)
const mockInvoicesDb = [
  {
    id: 'inv_001',
    tenantId: 'company_123',
    customerName: 'Cliente Exemplo S.A.',
    customerTaxId: '12.345.678/0001-90',
    issueDate: '2026-10-01',
    dueDate: '2026-10-15',
    status: 'PAGO',
    items: [
      { description: 'Plano Pro SaaS - Mensal', amount: 499.00 },
      { description: 'Usuários Adicionais (5x)', amount: 150.00 }
    ],
    total: 649.00
  }
];

/**
 * Rota GET /api/v1/invoices/:id/pdf
 * Gera e retorna o PDF de uma fatura para download.
 */
app.get('/api/v1/invoices/:id/pdf', tenantMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { companyId, companyName } = req.tenant;

    // 1. Busca os dados garantindo o isolamento de tenant
    const invoice = mockInvoicesDb.find(
      (inv) => inv.id === id && inv.tenantId === companyId
    );

    if (!invoice) {
      return res.status(404).json({ error: 'Fatura não encontrada.' });
    }

    // 2. Configura os cabeçalhos de resposta para download do PDF
    const filename = `fatura_${invoice.id}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    // 3. Inicializa o documento PDFKit
    const doc = new PDFDocument({ margin: 50, size: 'A4' });

    // Envia o fluxo do PDF direto na resposta HTTP
    doc.pipe(res);

    // --- CABEÇALHO DA EMPRESA (LOCATÁRIO) ---
    doc
      .fontSize(18)
      .text(companyName, { align: 'left' })
      .fontSize(10)
      .fillColor('#666666')
      .text(`ID do Locatário: ${companyId}`)
      .moveDown(1.5);

    // Linha divisória
    doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#cccccc').stroke().moveDown(1);

    // --- DETALHES DA FATURA ---
    doc
      .fillColor('#000000')
      .fontSize(14)
      .text(`FATURA #${invoice.id}`, { underline: true })
      .moveDown(0.5);

    doc
      .fontSize(10)
      .text(`Cliente: ${invoice.customerName}`)
      .text(`CNPJ/CPF: ${invoice.customerTaxId}`)
      .text(`Data de Emissão: ${invoice.issueDate}`)
      .text(`Data de Vencimento: ${invoice.dueDate}`)
      .text(`Status: ${invoice.status}`)
      .moveDown(1.5);

    // --- TABELA DE ITENS ---
    doc.fontSize(12).text('Itens da Fatura:', { bold: true }).moveDown(0.5);

    // Cabeçalho da Tabela
    const tableTop = doc.y;
    doc
      .fontSize(10)
      .text('Descrição', 50, tableTop, { width: 350 })
      .text('Valor (R$)', 420, tableTop, { width: 125, align: 'right' });

    doc.moveTo(50, doc.y + 2).lineTo(545, doc.y + 2).strokeColor('#eeeeee').stroke();

    let currentY = doc.y + 8;

    // Renderização dos Itens
    invoice.items.forEach((item) => {
      doc
        .text(item.description, 50, currentY, { width: 350 })
        .text(item.amount.toFixed(2), 420, currentY, { width: 125, align: 'right' });
      currentY += 20;
    });

    doc.moveTo(50, currentY).lineTo(545, currentY).strokeColor('#cccccc').stroke().moveDown(1);

    // --- TOTAL ---
    doc
      .fontSize(12)
      .fillColor('#000000')
      .text(`Total: R$ ${invoice.total.toFixed(2)}`, 420, currentY + 10, {
        width: 125,
        align: 'right'
      });

    // Finaliza o documento PDF
    doc.end();
  } catch (error) {
    console.error('Erro ao gerar relatório PDF:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Erro interno ao gerar o PDF da fatura.' });
    }
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});