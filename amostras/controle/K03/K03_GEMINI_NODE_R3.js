const express = require('express');
const helmet = require('helmet');
const PDFDocument = require('pdfkit');
const { z } = require('zod');

const app = express();

// A05:2021 - Security Misconfiguration: Cabeçalhos HTTP seguros
app.use(helmet());
app.use(express.json());

// --- MOCK DE BANCO DE DADOS E MIDDLEWARE DE AUTENTICAÇÃO ---

// Simulação de banco de dados multilocatário
const invoicesDb = {
  'inv_101': { id: 'inv_101', tenantId: 'tenant_A', amount: 250.00, dueDate: '2026-10-15', status: 'PAID', description: 'Plano Pro - Mensal' },
  'inv_102': { id: 'inv_102', tenantId: 'tenant_B', amount: 500.00, dueDate: '2026-10-20', status: 'PENDING', description: 'Plano Enterprise - Mensal' }
};

// Middleware simulado de autenticação/contexto
// Em produção, isso viria da validação do token JWT / Sessão
app.use((req, res, next) => {
  req.user = {
    id: 'usr_888',
    tenantId: 'tenant_A', // O usuário pertence à Empresa/Tenant A
    role: 'ADMIN'
  };
  next();
});

// --- VALIDAÇÃO DE ENTRADA (OWASP A03:2021 - Injection / Data Validation) ---

const paramsSchema = z.object({
  invoiceId: z.string().alphanumeric().max(32)
});

// --- ROTA DE GERAÇÃO E DOWNLOAD DE PDF ---

app.get('/api/v1/invoices/:invoiceId/download', async (req, res) => {
  try {
    // 1. Validação do parâmetro de entrada
    const validation = paramsSchema.safeParse(req.params);
    if (!validation.success) {
      return res.status(400).json({ error: 'Identificador de fatura inválido.' });
    }

    const { invoiceId } = validation.data;
    const currentTenantId = req.user.tenantId;

    // 2. Consulta no banco de dados isolada por Tenant (OWASP A01:2021 - Broken Access Control)
    // GARANTIA MULTILOCATÁRIA: O tenantId SEMPRE faz parte da cláusula de busca
    const invoice = invoicesDb[invoiceId];

    if (!invoice || invoice.tenantId !== currentTenantId) {
      // Retorna 404 para evitar inferência de existência de recursos de outros locatários
      return res.status(404).json({ error: 'Fatura não encontrada.' });
    }

    // 3. Configuração dos cabeçalhos HTTP para download seguro
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="fatura_${invoice.id}.pdf"`);
    // Prevenção de armazenamento em cache de dados sensíveis em proxies intermediários
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');

    // 4. Geração do relatório em PDF via Stream direto para a resposta HTTP
    const doc = new PDFDocument({ margin: 50 });

    // Envia o stream diretamente para a resposta, sem gravar arquivos em disco (evita Path Traversal / LFI)
    doc.pipe(res);

    // Cabeçalho do Documento
    doc.fontSize(20).text('RELATÓRIO DE FATURA', { align: 'center' });
    doc.moveDown(2);

    // Dados da Fatura
    doc.fontSize(12).text(`ID da Fatura: ${invoice.id}`);
    doc.text(`ID do Cliente (Tenant): ${invoice.tenantId}`);
    doc.text(`Descrição: ${invoice.description}`);
    doc.text(`Valor: R$ ${invoice.amount.toFixed(2)}`);
    doc.text(`Vencimento: ${invoice.dueDate}`);
    doc.text(`Status: ${invoice.status}`);

    doc.moveDown(2);
    doc.fontSize(10).fillColor('gray').text('Documento gerado automaticamente pela plataforma SaaS.', { align: 'center' });

    // Finaliza o PDF e encerra a conexão HTTP
    doc.end();

  } catch (error) {
    // OWASP A09:2021 - Security Logging and Monitoring Failures: Log detalhado no backend
    console.error(`[ERROR] Falha ao gerar PDF da fatura para o tenant ${req.user?.tenantId}:`, error);

    // Não expõe detalhes do erro interno para o cliente
    if (!res.headersSent) {
      return res.status(500).json({ error: 'Erro interno ao processar o relatório.' });
    }
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});