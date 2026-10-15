const express = require('express');
const PDFDocument = require('pdfkit');

const app = express();
app.use(express.json());

// Middleware simulado de autenticação/contexto do Tenant
// Em produção, esses dados viriam da validação de um token JWT ou sessão.
const authMiddleware = (req, res, next) => {
  req.user = {
    id: 'usr_123',
    tenantId: 'tenant_abc_456', // ID da empresa cliente logada
    role: 'admin'
  };
  next();
};

// Banco de dados simulado (mesma base para todos os tenants)
const mockInvoicesDatabase = [
  {
    id: 'inv_2026_001',
    tenantId: 'tenant_abc_456',
    customerName: 'Acme Corp LTDA',
    customerCnpj: '12.345.678/0001-90',
    issueDate: '2026-10-01',
    dueDate: '2026-10-15',
    amount: 1450.00,
    status: 'Pendente',
    items: [
      { description: 'Plano SaaS Enterprise - Mensalidade', qty: 1, unitPrice: 1200.00 },
      { description: 'Usuários Adicionais (5x)', qty: 5, unitPrice: 50.00 }
    ]
  }
];

/**
 * GET /api/v1/invoices/:id/download
 * Rota para geração e download de relatório de fatura em PDF
 */
app.get('/api/v1/invoices/:id/download', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { tenantId } = req.user;

    // 1. Busca e isolamento de Tenant (CRÍTICO em SaaS multilocatário)
    // A consulta SEMPRE deve filtrar explicitamente pelo tenantId
    const invoice = mockInvoicesDatabase.find(
      (inv) => inv.id === id && inv.tenantId === tenantId
    );

    if (!invoice) {
      return res.status(404).json({ error: 'Fatura não encontrada.' });
    }

    // 2. Configuração dos cabeçalhos HTTP para download de PDF
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename=fatura_${invoice.id}.pdf`
    );

    // 3. Inicialização do documento PDFKit
    const doc = new PDFDocument({ margin: 50, size: 'A4' });

    // Redireciona o stream do PDF diretamente para o objeto de resposta (res)
    doc.pipe(res);

    // --- CABEÇALHO ---
    doc
      .fontSize(20)
      .text('PLATAFORMA SAAS', { align: 'left' })
      .fontSize(10)
      .text('Relatório de Fatura de Serviços', { align: 'left' })
      .moveDown();

    doc
      .moveTo(50, doc.y)
      .lineTo(545, doc.y)
      .stroke();

    doc.moveDown();

    // --- DADOS DA FATURA E CLIENTE ---
    const startY = doc.y;
    doc
      .fontSize(12)
      .text(`Fatura ID: ${invoice.id}`, 50, startY)
      .text(`Status: ${invoice.status}`)
      .text(`Emissão: ${invoice.issueDate}`)
      .text(`Vencimento: ${invoice.dueDate}`);

    doc
      .fontSize(12)
      .text(`Cliente: ${invoice.customerName}`, 300, startY)
      .text(`CNPJ: ${invoice.customerCnpj}`);

    doc.moveDown(2);

    // --- TABELA DE ITENS ---
    const tableTop = doc.y;
    doc.fontSize(10).font('Helvetica-Bold');
    doc.text('Descrição', 50, tableTop);
    doc.text('Qtd', 330, tableTop, { width: 50, align: 'right' });
    doc.text('Preço Unit.', 390, tableTop, { width: 70, align: 'right' });
    doc.text('Total', 470, tableTop, { width: 75, align: 'right' });

    doc
      .moveTo(50, tableTop + 15)
      .lineTo(545, tableTop + 15)
      .stroke();

    let position = tableTop + 25;
    doc.font('Helvetica');

    invoice.items.forEach((item) => {
      const itemTotal = item.qty * item.unitPrice;
      doc.text(item.description, 50, position);
      doc.text(item.qty.toString(), 330, position, { width: 50, align: 'right' });
      doc.text(`R$ ${item.unitPrice.toFixed(2)}`, 390, position, { width: 70, align: 'right' });
      doc.text(`R$ ${itemTotal.toFixed(2)}`, 470, position, { width: 75, align: 'right' });
      position += 20;
    });

    doc
      .moveTo(50, position)
      .lineTo(545, position)
      .stroke();

    // --- TOTALIZADOR ---
    doc
      .moveDown()
      .fontSize(12)
      .font('Helvetica-Bold')
      .text(`Valor Total: R$ ${invoice.amount.toFixed(2)}`, 350, position + 15, {
        width: 195,
        align: 'right'
      });

    // --- RODAPÉ ---
    doc
      .fontSize(8)
      .font('Helvetica')
      .text(
        'Este documento é um demonstrativo de cobrança referente à sua assinatura SaaS.',
        50,
        700,
        { align: 'center', width: 495 }
      );

    // Finaliza a gravação do PDF e fecha a conexão do stream
    doc.end();
  } catch (error) {
    console.error('Erro ao gerar relatório em PDF:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Erro interno ao gerar o PDF.' });
    }
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});