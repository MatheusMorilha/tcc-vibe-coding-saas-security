const express = require('express');
const PDFDocument = require('pdfkit');
const { z } = require('zod');

const router = express.Router();

// Esquema de validação dos parâmetros de entrada
const invoiceParamsSchema = z.object({
  invoiceId: z.string().uuid({ message: "O ID da fatura deve ser um UUID válido." })
});

/**
 * Função simulada para buscar a fatura no banco de dados.
 * Em produção, utilize queries parametrizadas (ex: Prisma, TypeORM, Knex) para evitar SQL Injection.
 */
async function findInvoiceByIdAndTenant(invoiceId, tenantId){
  // CRÍTICO (A01:2021 - Broken Access Control):
  // A consulta DEVE obrigatoriamente incluir o tenantId na cláusula WHERE.

  // Exemplo conceitual de query segura:
  // return await db.invoice.findFirst({ where: { id: invoiceId, tenantId: tenantId } });

  if (invoiceId !== "123e4567-e89b-12d3-a456-426614174000") {
    return null;
  }

  return {
    id: invoiceId,
    tenantId: tenantId,
    code: "INV-2026-001",
    customerName: "Empresa Exemplo Ltda",
    amount: "R$ 1.250,00",
    dueDate: "2026-10-15",
    status: "Paga",
    items: [
      { description: "Assinatura Plano Enterprise - Outubro/2026", price: "R$ 1.250,00" }
    ]
  };
}

/**
 * Middleware simulado de autenticação/contexto.
 * Preenche req.user e req.tenantId a partir do token JWT validado.
 */
function authenticateAndSetContext(req, res, next){
  // Simulação de usuário autenticado extraído do JWT
  req.tenantId = "tenant_company_abc_123";
  req.userId = "user_456";
  next();
}

/**
 * GET /api/v1/invoices/:invoiceId/download
 * Gera e retorna o relatório em PDF para download direto via stream.
 */
router.get(
  '/api/v1/invoices/:invoiceId/download',
  authenticateAndSetContext,
  async (req, res) => {
    try {
      // 1. Validação de Entrada (A03:2021 - Injection / Input Validation)
      const parseResult = invoiceParamsSchema.safeParse(req.params);
      if (!parseResult.success) {
        return res.status(400).json({
          error: "Requisição inválida.",
          details: parseResult.error.issues.map(issue => issue.message)
        });
      }

      const { invoiceId } = parseResult.data;
      const tenantId = req.tenantId;

      // 2. Busca com Isolamento Multilocatário (A01:2021 - Broken Access Control / BOLA)
      const invoice = await findInvoiceByIdAndTenant(invoiceId, tenantId);

      if (!invoice) {
        // Retornar 404 para não expor a existência de recursos de outros locatários
        return res.status(404).json({ error: "Fatura não encontrada." });
      }

      // 3. Configuração dos Headers de Resposta e Segurança (A05:2021 - Security Misconfiguration)
      const filename = `fatura_${invoice.code}.pdf`;

      res.setHeader('Content-Type', 'application/pdf');
      // Content-Disposition: attachment força o download sem executar scripts no navegador
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      // Evita o armazenamento do PDF em caches intermediários/públicos
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');

      // 4. Geração do PDF em Stream (A04:2021 - Insecure Design / Memory Safety)
      // O documento é transmitido via pipe diretamente na resposta sem salvar em disco ou carregar em RAM
      const doc = new PDFDocument({ margin: 50 });
      doc.pipe(res);

      // Cabeçalho
      doc.fontSize(20).text('Relatório de Fatura', { align: 'center' });
      doc.moveDown();

      // Detalhes da Fatura
      doc.fontSize(12).text(`Código: ${invoice.code}`);
      doc.text(`Cliente: ${invoice.customerName}`);
      doc.text(`Vencimento: ${invoice.dueDate}`);
      doc.text(`Status: ${invoice.status}`);
      doc.moveDown();

      // Tabela de Itens
      doc.fontSize(14).text('Itens', { underline: true });
      doc.moveDown(0.5);

      invoice.items.forEach((item) => {
        doc.fontSize(10).text(`${item.description} - ${item.price}`);
      });

      doc.moveDown();
      doc.fontSize(12).text(`Total: ${invoice.amount}`, { align: 'right' });

      // Finaliza a gravação no stream
      doc.end();

    } catch (error) {
      // 5. Tratamento de Erros e Logging Seguro (A09:2021 - Security Logging & Monitoring / Sensitive Data Exposure)
      console.error(`[ERROR] Falha ao gerar PDF da fatura para o tenant ${req.tenantId}:`, error.stack);

      if (!res.headersSent) {
        // Retorna mensagem genérica para evitar vazar stack traces ou detalhes da infraestrutura
        res.status(500).json({ error: "Ocorreu um erro interno ao processar a fatura." });
      }
    }
  }
);

module.exports = router;