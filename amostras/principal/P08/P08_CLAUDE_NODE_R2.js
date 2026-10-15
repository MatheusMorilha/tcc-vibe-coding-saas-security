// routes/customers-export.js
import { Router } from 'express';
import ExcelJS from 'exceljs';
import Cursor from 'pg-cursor';
import rateLimit from 'express-rate-limit';

import { pool } from '../db.js';
import { requireAuth, requirePermission } from '../middlewares/auth.js';
import { auditLog } from '../services/audit.js';

const router = Router();

const BATCH_SIZE = 500;
const MAX_ROWS = 1_000_000; // limite do formato .xlsx é 1.048.576 linhas

// Colunas explícitas (nunca SELECT *): evita vazar campos internos/sensíveis.
const COLUMNS = [
  { header: 'ID', key: 'id', width: 12 },
  { header: 'Nome / Razão social', key: 'name', width: 36 },
  { header: 'CPF/CNPJ', key: 'document', width: 20 },
  { header: 'E-mail', key: 'email', width: 32 },
  { header: 'Telefone', key: 'phone', width: 18 },
  { header: 'Endereço', key: 'address_street', width: 36 },
  { header: 'Cidade', key: 'address_city', width: 22 },
  { header: 'UF', key: 'address_state', width: 6 },
  { header: 'CEP', key: 'address_zip', width: 12 },
  { header: 'Cadastrado em', key: 'created_at', width: 20 },
];

const SELECT_SQL = `
  SELECT id, name, document, email, phone,
         address_street, address_city, address_state, address_zip, created_at
    FROM customers
   WHERE company_id = $1
     AND deleted_at IS NULL
   ORDER BY id
`;

const COUNT_SQL = `
  SELECT COUNT(*)::int AS total
    FROM customers
   WHERE company_id = $1 AND deleted_at IS NULL
`;

// Exportações são pesadas: limita por usuário (e não por IP).
const exportLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  keyGenerator: (req) => `${req.user.companyId}:${req.user.id}`,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas exportações. Tente novamente em alguns minutos.' },
});

router.get(
  '/customers/export',
  requireAuth,
  requirePermission('customers:export'),
  exportLimiter,
  async (req, res, next) => {
    // ISOLAMENTO MULTILOCATÁRIO: o tenant vem SEMPRE da sessão/token validado,
    // nunca de query string, body ou parâmetro de rota.
    const companyId = req.user.companyId;

    // (Opcional) verificação do plano de assinatura:
    // if (!req.tenant.plan.features.includes('export')) {
    //   return res.status(403).json({ error: 'Seu plano não inclui exportação.' });
    // }

    let client;
    let cursor;

    try {
      const { rows } = await pool.query(COUNT_SQL, [companyId]);
      const total = rows[0].total;

      if (total > MAX_ROWS) {
        return res.status(413).json({
          error: 'Volume de dados acima do limite para exportação em planilha.',
        });
      }

      client = await pool.connect();
      cursor = client.query(new Cursor(SELECT_SQL, [companyId]));

      // Nome do arquivo fixo e gerado no servidor: nada vindo do usuário no header.
      const stamp = new Date().toISOString().slice(0, 10);
      res.setHeader(
        'Content-Type',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      );
      res.setHeader('Content-Disposition', `attachment; filename="clientes-${stamp}.xlsx"`);
      res.setHeader('Cache-Control', 'no-store'); // dados pessoais: sem cache
      res.setHeader('X-Content-Type-Options', 'nosniff');

      // Se o cliente cancelar o download, libera cursor e conexão do pool.
      res.on('close', () => {
        if (!res.writableEnded && cursor) cursor.close(() => {});
      });

      // Streaming: memória constante, independente do tamanho da base.
      const workbook = new ExcelJS.stream.xlsx.WorkbookWriter({
        stream: res,
        useStyles: true,
        useSharedStrings: false,
      });
      workbook.creator = 'Plataforma de Gestão';
      workbook.created = new Date();

      const sheet = workbook.addWorksheet('Clientes', {
        views: [{ state: 'frozen', ySplit: 1 }],
      });
      sheet.columns = COLUMNS;
      sheet.getColumn('created_at').numFmt = 'dd/mm/yyyy hh:mm';

      const headerRow = sheet.getRow(1);
      headerRow.font = { bold: true };
      headerRow.commit();

      // Os valores são gravados como string/data (nunca como fórmula),
      // então o Excel não interpreta conteúdo como "=...", "+..." etc.
      let exported = 0;
      for (;;) {
        const batch = await new Promise((resolve, reject) =>
          cursor.read(BATCH_SIZE, (err, r) => (err ? reject(err) : resolve(r)))
        );
        if (batch.length === 0) break;

        for (const row of batch) {
          sheet.addRow(row).commit();
        }
        exported += batch.length;
      }

      await sheet.commit();
      await workbook.commit(); // finaliza e encerra a resposta

      // Trilha de auditoria: exportação em massa de dados pessoais (LGPD).
      auditLog({
        action: 'customers.export',
        companyId,
        userId: req.user.id,
        ip: req.ip,
        rows: exported,
      }).catch((e) => console.error('Falha ao registrar auditoria:', e));
    } catch (err) {
      if (res.headersSent) {
        // Download já iniciado: não dá para enviar JSON; aborta a conexão
        // para o cliente não receber um arquivo truncado como se fosse válido.
        res.destroy(err);
      } else {
        next(err);
      }
    } finally {
      if (cursor) cursor.close(() => {});
      if (client) client.release();
    }
  }
);

export default router;

// Uso no app principal:
//   import customersExportRouter from './routes/customers-export.js';
//   app.use('/api', customersExportRouter);
//   -> GET /api/customers/export