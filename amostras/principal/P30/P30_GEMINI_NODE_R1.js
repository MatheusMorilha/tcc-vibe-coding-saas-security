const express = require('express');
const multer = require('multer');
const ExcelJS = require('exceljs');

const router = express.Router();

// Configuração do Multer para armazenar o arquivo temporariamente na memória
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // Limite de 10MB
  fileFilter: (req, file, cb) => {
    const allowedMimeTypes = [
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'text/csv'
    ];
    if (allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Formato de arquivo inválido. Envie um arquivo .xlsx ou .csv.'));
    }
  }
});

/**
 * Middleware de Autenticação/Contexto Tenant (Simulado)
 * Extrai o tenant_id autenticado no token JWT/Sessão do usuário.
 */
function extractTenantContext(req, res, next){
  // Em produção, isso viria de req.user.tenant_id após decodificar o token de autenticação
  const tenantId = req.headers['x-tenant-id'] || req.user?.tenantId;

  if (!tenantId) {
    return res.status(401).json({ error: 'Contexto de empresa (Tenant ID) não informado ou inválido.' });
  }

  req.tenantId = tenantId;
  next();
}

/**
 * POST /api/v1/customers/batch-import
 * Importa clientes em lote para a empresa autenticada.
 */
router.post(
  '/api/v1/customers/batch-import',
  extractTenantContext,
  upload.single('file'),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'Nenhum arquivo foi enviado.' });
    }

    const tenantId = req.tenantId;
    const summary = {
      totalRecords: 0,
      processed: 0,
      failed: 0,
      errors: []
    };

    try {
      // 1. Leitura da planilha em memória
      const workbook = new ExcelJS.Workbook();
      await workbook.xlsx.load(req.file.buffer);

      const worksheet = workbook.worksheets[0]; // Pega a primeira aba
      if (!worksheet) {
        return res.status(400).json({ error: 'A planilha informada está vazia.' });
      }

      const rowsToInsert = [];
      const batchSize = 500; // Tamanho do lote para inserção no banco de dados

      // 2. Leitura e validação das linhas (Assumindo cabeçalho na linha 1)
      worksheet.eachRow({ includeEmpty: false }, (row, rowNumber) => {
        if (rowNumber === 1) return; // Pula o cabeçalho

        summary.totalRecords++;

        const name = row.getCell(1).value?.toString()?.trim();
        const email = row.getCell(2).value?.toString()?.trim()?.toLowerCase();
        const phone = row.getCell(3).value?.toString()?.trim();
        const document = row.getCell(4).value?.toString()?.trim();

        // Validação básica por registro
        if (!name || !email) {
          summary.failed++;
          summary.errors.push({
            row: rowNumber,
            email: email || null,
            reason: 'Campos obrigatórios ausentes (Nome e E-mail são obrigatórios).'
          });
          return;
        }

        rowsToInsert.push({
          tenant_id: tenantId, // ISOLAMENTO MULTI-TENANT
          name,
          email,
          phone: phone || null,
          document: document || null,
          created_at: new Date()
        });
      });

      // 3. Processamento em Lotes (Batch Insert) no Banco de Dados
      for (let i = 0; i < rowsToInsert.length; i += batchSize) {
        const batch = rowsToInsert.slice(i, i + batchSize);

        try {
          /**
           * Exemplo com ORM/Query Builder (ex: Knex / Prisma / TypeORM):
           * await db('customers').insert(batch).onConflict(['tenant_id', 'email']).ignore();
           *
           * Garantindo query isolada por tenant e evitando N+1 queries.
           */
          await saveBatchToDatabase(tenantId, batch);
          summary.processed += batch.length;
        } catch (dbError) {
          // Se o lote falhar, registra o erro para os itens daquele lote
          summary.failed += batch.length;
          summary.errors.push({
            batchRange: `${i + 2} - ${i + 2 + batch.length - 1}`,
            reason: `Erro ao salvar lote no banco de dados: ${dbError.message}`
          });
        }
      }

      // 4. Retorno do Resumo de Processamento
      return res.status(200).json({
        message: 'Processamento de importação concluído.',
        summary
      });

    } catch (error) {
      console.error('Erro no processamento da planilha:', error);
      return res.status(500).json({
        error: 'Erro interno ao processar o arquivo de importação.',
        details: error.message
      });
    }
  }
);

/**
 * Função utilitária simulando inserção em lote com isolamento por Tenant
 */
async function saveBatchToDatabase(tenantId, batchRecords){
  // Simulação de inserção no banco de dados
  // Em uma aplicação real:
  // await knex('customers').insert(batchRecords.map(r => ({ ...r, tenant_id: tenantId })));
  return Promise.resolve();
}

module.exports = router;