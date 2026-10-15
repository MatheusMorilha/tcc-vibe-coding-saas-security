const Express = require('express');
const PDFDocument = require('pdfkit');

const router = Express.Router();

/**
 * Simulação de busca no banco de dados isolado por Tenant.
 * Em produção, essa busca deve validar obrigatoriamente o tenant_id do contexto autenticado.
 */
async function getInvoiceByIdAndTenant(invoiceId, tenantId){
  // Exemplo de dados retornados do banco
  const mockInvoice = {
    id: invoiceId,
    tenantId: tenantId,
    customerName: 'Empresa Cliente LTDA',
    customerCnpj: '12.345.678/0001-90',
    issueDate: '2026-10-01',
    dueDate: '2026-10-15',
    status: 'PAGO',
    items: [
      { description: 'Assinatura Plano Enterprise - Mensal', amount: 1, unitPrice: 1200.00 },
      { description: 'Usuários Adicionais (5x)', amount: 5, unitPrice: 50.00 }
    ],
    total: 1450.00
  };

  // Se a fatura não existir ou não pertencer ao tenant autenticado, retorna null
  if (mockInvoice.tenantId !== tenantId) {
    return null;
  }

  return mockInvoice;
}

/**
 * GET /api/v1/invoices/:id/download
 * Rota para geração e download do PDF da fatura.
 */
router.get('/invoices/:id/download', async (req, res) => {
  try {
    const invoiceId = req.params.id;

    // O tenant_id DEVE vir do middleware de autenticação (ex: JWT / Session)
    // NUNCA confie em tenant_id passado por parâmetro ou query string no frontend
    const tenantId = req.user?.tenantId || 'tenant_company_123';

    // 1. Busca e validação do isolamento multilocatário
    const invoice = await getInvoiceByIdAndTenant(invoiceId, tenantId);

    if (!invoice) {
      return res.status(404).json({
        error: 'Fatura não encontrada ou acesso não autorizado para este locatário.'
      });
    }

    // 2. Configuração dos Headers HTTP para Download/Stream de PDF
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="fatura_${invoice.id}.pdf"`
    );

    // 3. Inicialização do documento PDFKit
    const doc = new PDFDocument({ margin: 50, size: 'A4' });

    // Redireciona o stream do PDF diretamente para a resposta HTTP (response Express)
    doc.pipe(res);

    // 4. Construção do layout do PDF

    // Cabeçalho / Logo & Identificação do SaaS
    doc.fontSize(20).text('SaaS Management Platform', { align: 'left' });
    doc.fontSize(10).fillColor('#666666').text('Relatório Financeiro de Cobrança', { align: 'left' });
    doc.moveDown();

    // Divisor
    doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#cccccc').stroke();
    doc.moveDown();

    // Detalhes da Fatura e Locatário
    doc.fillColor('#000000').fontSize(12).text(`Fatura nº: ${invoice.id}`);
    doc.fontSize(10)
       .text(`Cliente: ${invoice.customerName}`)
       .text(`CNPJ: ${invoice.customerCnpj}`)
       .text(`Data de Emissão: ${invoice.issueDate}`)
       .text(`Data de Vencimento: ${invoice.dueDate}`)
       .text(`Status: ${invoice.status}`);
    doc.moveDown();

    // Tabela de Itens (Cabeçalho)
    const tableTop = doc.y;
    doc.font('Helvetica-Bold');
    doc.text('Descrição', 50, tableTop);
    doc.text('Qtd', 330, tableTop, { width: 50, align: 'right' });
    doc.text('Preço Unit.', 390, tableTop, { width: 70, align: 'right' });
    doc.text('Total', 470, tableTop, { width: 75, align: 'right' });

    doc.moveTo(50, tableTop + 15).lineTo(545, tableTop + 15).strokeColor('#aaaaaa').stroke();

    // Linhas dos Itens
    let yPosition = tableTop + 25;
    doc.font('Helvetica');

    invoice.items.forEach(item => {
      const itemTotal = item.amount * item.unitPrice;

      doc.text(item.description, 50, yPosition, { width: 270 });
      doc.text(item.amount.toString(), 330, yPosition, { width: 50, align: 'right' });
      doc.text(`R$ ${item.unitPrice.toFixed(2)}`, 390, yPosition, { width: 70, align: 'right' });
      doc.text(`R$ ${itemTotal.toFixed(2)}`, 470, yPosition, { width: 75, align: 'right' });

      yPosition += 20;
    });

    doc.moveTo(50, yPosition).lineTo(545, yPosition).strokeColor('#cccccc').stroke();

    // Valor Total
    doc.font('Helvetica-Bold').fontSize(12);
    doc.text(
      `Total Geral: R$ ${invoice.total.toFixed(2)}`,
      350,
      yPosition + 15,
      { width: 195, align: 'right' }
    );

    // Rodapé
    doc.fontSize(8).fillColor('#888888').text(
      'Documento gerado automaticamente pela plataforma SaaS.',
      50,
      750,
      { align: 'center', width: 495 }
    );

    // Finaliza a gravação do PDF (fecha o stream)
    doc.end();

  } catch (error) {
    console.error('Erro na geração do PDF:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Erro interno ao processar a geração da fatura.' });
    }
  }
});

module.exports = router;