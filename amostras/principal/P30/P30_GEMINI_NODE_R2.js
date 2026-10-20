const express = require('express');
const multer = require('multer');
const XLSX = require('xlsx');
const { Pool } = require('pg');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// Configuração do pool de conexões (exemplo com PostgreSQL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

/**
 * Middleware simulado de autenticação/contexto do Tenant
 * Extrai o tenantId (empresa) e o plano a partir do token JWT ou headers da requisição.
 */
const tenantContextMiddleware = (req, res, next) => {
  const tenantId = req.headers['x-tenant-id'];
  const subscriptionPlan = req.headers['x-subscription-plan']; // Ex: 'free', 'pro', 'enterprise'

  if (!tenantId) {
    return res.status(400).json({ error: 'Contexto de tenant não fornecido.' });
  }

  req.tenant = {
    id: tenantId,
    plan: subscriptionPlan || 'free'
  };

  next();
};

/**
 * Limites de importação por plano de assinatura
 */
const PLAN_LIMITS = {
  free: 100,
  pro: 5000,
  enterprise: 50000
};

/**
 * Rota para importação em lote de clientes via planilha (XLSX/CSV)
 * Rota: POST /api/clients/import
 */
router.post('/import', tenantContextMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
  }

  const tenantId = req.tenant.id;
  const userPlan = req.tenant.plan;
  const maxLimit = PLAN_LIMITS[userPlan] || PLAN_LIMITS['free'];

  let client;
  try {
    // 1. Leitura do arquivo em memória usando a biblioteca 'xlsx'
    const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    
    // Converte a planilha para array de objetos JSON
    const rows = XLSX.utils.sheet_to_json(worksheet);

    if (rows.length === 0) {
      return res.status(400).json({ error: 'A planilha está vazia.' });
    }

    // 2. Validação do plano de assinatura da empresa (Multitenancy / Limites)
    if (rows.length > maxLimit) {
      return res.status(403).json({
        error: 'Limite excedido',
        message: `Seu plano atual (${userPlan}) permite importar no máximo ${maxLimit} registros por vez. O arquivo enviado possui ${rows.length} registros.`
      });
    }

    client = await pool.connect();
    await client.query('BEGIN');

    let successCount = 0;
    let errorCount = 0;
    const errors = [];

    // 3. Processamento iterativo dos registros com isolamento por tenantId
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const rowNumber = i + 2; // Linha real considerando o cabeçalho

      // Validação básica dos campos obrigatórios
      const { name, email, document } = row;
      if (!name || !email) {
        errorCount++;
        errors.push({ linha: rowNumber, motivo: 'Campos obrigatórios (name e/ou email) ausentes.' });
        continue;
      }

      try {
        // Inserção com segurança contra vazamento de dados entre tenants (tenant_id obrigatório)
        const query = `
          INSERT INTO clients (tenant_id, name, email, document, created_at, updated_at)
          VALUES ($1, $2, $3, $4, NOW(), NOW())
          ON CONFLICT (tenant_id, email) 
          DO UPDATE SET 
            name = EXCLUDED.name,
            document = EXCLUDED.document,
            updated_at = NOW();
        `;
        
        const values = [tenantId, name, email, document || null];
        await client.query(query, values);
        successCount++;
      } catch (err) {
        errorCount++;
        errors.push({ linha: rowNumber, motivo: err.message });
      }
    }

    await client.query('COMMIT');

    // 4. Retorno do resumo do processamento
    return res.status(200).json({
      message: 'Processamento de importação concluído.',
      summary: {
        totalRegistros: rows.length,
        sucessos: successCount,
        erros: errorCount,
        detalhesErros: errors.length > 0 ? errors : undefined
      }
    });

  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
    }
    console.error('Erro na importação em lote:', error);
    return res.status(500).json({ error: 'Erro interno ao processar a planilha.' });
  } finally {
    if (client) {
      client.release();
    }
  }
});

module.exports = router;