const express = require('express');
const router = express.Router();
const { param, validationResult } = require('express-validator');
const PDFDocument = require('pdfkit');

/**
 * Função simulada de acesso ao banco de dados.
 * Em produção, utilize ORM/Query Builder com bind parameters (evita SQL Injection - OWASP A03).
 */
async function findInvoiceByIdAndTenant(invoiceId, tenantId){
  // Simulação de banco de dados
  const mockDatabase = [
    {
      id: 'inv_12345',
      tenantId: 'tenant_abc',
      customerName: 'Empresa Cliente Exemplo Ltda',
      amount: 1499.90,
      status: 'PAGO',
      dueDate: '2026-10-15',
      createdAt: '2026-10-01',
      items: [
        { description: 'Plano SaaS Enterprise - Mensal', value: 1499.90 }
      ]
    }
  ];

  return mockDatabase.find(
    (inv) => inv.id === invoiceId && inv.tenantId === tenantId
  ) || null;
}

/**
 * GET /api/v1/invoices/:id/download
 * Gera e retorna o relatório em PDF da fatura solicitada.
 */
router.get(
  '/invoices/:id/download',
  [
    // OWASP A03: Validação estrita de entrada (Input Validation)
    param('id')
      .isAlphanumeric('en-US', { ignore: '_-' })
      .withMessage('ID de fatura inválido.')
      .escape()
  ],
  async (req, res, next) => {
    try {
      // 1. Validação de erros de entrada
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { id: invoiceId } = req.params;

      // OWASP A01: Broken Access Control
      // O tenantId DEVE vir do contexto de autenticação validado (JWT/Session), NUNCA do corpo da requisição ou da URL.
      const tenantId = req.user?.tenantId;

      if (!tenantId) {
        return res.status(401).json({ error: 'Acesso não autorizado. Contexto de tenant ausente.' });
      }

      // 2. Busca o registro no banco garantindo o isolamento multi-tenant
      const invoice = await findInvoiceByIdAndTenant(invoiceId, tenantId);

      // Trata registros não encontrados sem expor dados de outros tenants
      if (!invoice) {
        return res.status(404).json({ error: 'Fatura não encontrada.' });
      }

      // OWASP A02: Cryptographic Failures & OWASP A05: Security Misconfiguration
      // Define os cabeçalhos de resposta apropriados para download de arquivo e prevenção de Sniffing
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="fatura_${invoice.id}.pdf"`);
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

      // 3. Inicialização e geração do PDF via Stream
      const doc = new PDFDocument({ margin: 50, size: 'A4' });

      // Envia o fluxo de dados diretamente para a resposta HTTP
      doc.pipe(res);

      // Cabeçalho do PDF
      doc
        .fontSize(20)
        .text('Relatório de Fatura', { align: 'center' })
        .moveDown();

      // Dados da Fatura
      doc
        .fontSize(12)
        .text(`Fatura ID: ${invoice.id}`)
        .text(`Cliente: ${invoice.customerName}`)
        .text(`Data de Emissão: ${invoice.createdAt}`)
        .text(`Data de Vencimento: ${invoice.dueDate}`)
        .text(`Status: ${invoice.status}`)
        .moveDown();

      // Linha separadora
      doc
        .moveTo(50, doc.y)
        .lineTo(545, doc.y)
        .stroke()
        .moveDown();

      // Detalhes dos Itens
      doc.fontSize(14).text('Itens da Fatura:', { underline: true }).moveDown(0.5);

      invoice.items.forEach((item) => {
        doc
          .fontSize(11)
          .text(`${item.description} - R$ ${item.value.toFixed(2)}`);
      });

      doc.moveDown();
      doc
        .fontSize(13)
        .text(`Valor Total: R$ ${invoice.amount.toFixed(2)}`, { align: 'right' });

      // Finaliza a escrita do documento
      doc.end();

    } catch (err) {
      // OWASP A05 / OWASP A10: Não expõe detalhes do erro de infraestrutura/código para o cliente
      next(err);
    }
  }
);

module.exports = router;

const express = require('express');
const helmet = require('helmet');
const invoiceRoutes = require('./routes/invoice');

const app = express();

// OWASP A05: Helmet adiciona cabeçalhos HTTP focados em segurança (HSTS, CSP, X-Frame-Options, etc.)
app.use(helmet());

app.use(express.json({ limit: '10kb' })); // Limita o payload para prevenir ataques DoS

// Middleware simulado de autenticação (JWT)
app.use((req, res, next) => {
  // Em produção, este objeto é preenchido após validar e decodificar o Bearer Token
  req.user = {
    id: 'usr_999',
    tenantId: 'tenant_abc',
    role: 'ADMIN'
  };
  next();
});

// Registro das rotas
app.use('/api/v1', invoiceRoutes);

// OWASP A05: Handler global de erro para evitar vazamento de Stack Traces
app.use((err, req, res, next) => {
  console.error('[ERRO INTERNO]:', err.stack); // Log interno para auditoria (OWASP A09)
  res.status(500).json({ error: 'Ocorreu um erro interno ao processar sua solicitação.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando com segurança na porta ${PORT}`);
});