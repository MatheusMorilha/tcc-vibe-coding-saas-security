'use strict';

/**
 * GET /api/clientes/exportar
 *
 * Exporta os dados cadastrais dos clientes da empresa do usuário autenticado
 * para um arquivo .xlsx, enviado em streaming (baixo consumo de memória).
 *
 * Pontos de segurança (multilocatário):
 *  - O tenant (empresa) vem SEMPRE da sessão/token validado, nunca de
 *    query string, body ou headers controlados pelo cliente.
 *  - Toda consulta é filtrada por company_id.
 *  - Exige permissão específica e plano ativo que inclua exportação.
 *  - Limite de linhas e rate limit para evitar abuso/exfiltração em massa.
 *  - Auditoria de cada exportação (LGPD).
 */

const express = require('express');
const rateLimit = require('express-rate-limit');
const ExcelJS = require('exceljs');
const QueryStream = require('pg-query-stream');

const pool = require('../db'); // instância de pg.Pool
const { authenticate } = require('../middlewares/auth'); // valida JWT/sessão e preenche req.user

const router = express.Router();

const MAX_EXPORT_ROWS = 100000;

// No máximo 5 exportações por usuário a cada 10 minutos
const exportLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.user.companyId}:${req.user.id}`,
  message: { error: 'Limite de exportações excedido. Tente novamente mais tarde.' },
});

// Garante permissão do usuário e plano ativo da empresa
async function authorizeExport(req, res, next) {
  try {
    const { companyId, permissions = [] } = req.user;

    if (!companyId) {
      return res.status(403).json({ error: 'Acesso negado.' });
    }
    if (!permissions.includes('customers:export')) {
      return res.status(403).json({ error: 'Sem permissão para exportar clientes.' });
    }

    const { rows } = await pool.query(
      `SELECT p.allows_export
         FROM subscriptions s
         JOIN plans p ON p.id = s.plan_id
        WHERE s.company_id = $1
          AND s.status = 'active'
          AND (s.expires_at IS NULL OR s.expires_at > NOW())
        LIMIT 1`,
      [companyId]
    );

    if (rows.length === 0) {
      return res.status(402).json({ error: 'Assinatura inativa ou expirada.' });
    }
    if (!rows[0].allows_export) {
      return res.status(403).json({ error: 'Seu plano não inclui exportação de dados.' });
    }

    return next();
  } catch (err) {
    return next(err);
  }
}

const COLUMNS = [
  { header: 'ID', key: 'id', width: 38 },
  { header: 'Nome / Razão Social', key: 'name', width: 40 },
  { header: 'CPF/CNPJ', key: 'document', width: 20 },
  { header: 'E-mail', key: 'email', width: 35 },
  { header: 'Telefone', key: 'phone', width: 18 },
  { header: 'Endereço', key: 'address', width: 45 },
  { header: 'Cidade', key: 'city', width: 22 },
  { header: 'UF', key: 'state', width: 6 },
  { header: 'CEP', key: 'zip_code', width: 12 },
  { header: 'Cadastrado em', key: 'created_at', width: 20 },
];

// Mantém valores como texto puro; strings no XLSX não são avaliadas como
// fórmulas, mas normalizamos o tipo para evitar surpresas.
const toCell = (v) => {
  if (v === null || v === undefined) return '';
  if (v instanceof Date) return v;
  return typeof v === 'number' ? v : String(v);
};

router.get(
  '/clientes/exportar',
  authenticate,
  exportLimiter,
  authorizeExport,
  async (req, res, next) => {
    const { companyId, id: userId } = req.user;
    const client = await pool.connect();
    let released = false;
    const release = (err) => {
      if (!released) {
        released = true;
        client.release(err);
      }
    };

    try {
      // Verifica o volume antes de iniciar o envio
      const { rows } = await client.query(
        'SELECT COUNT(*)::int AS total FROM customers WHERE company_id = $1',
        [companyId]
      );
      const total = rows[0].total;

      if (total > MAX_EXPORT_ROWS) {
        release();
        return res.status(413).json({
          error: `A exportação excede o limite de ${MAX_EXPORT_ROWS} registros. Aplique filtros ou contate o suporte.`,
        });
      }

      const stamp = new Date().toISOString().slice(0, 10);
      res.setHeader(
        'Content-Type',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      );
      // Nome de arquivo fixo: nada vindo do usuário entra no header
      res.setHeader('Content-Disposition', `attachment; filename="clientes-${stamp}.xlsx"`);
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');

      const workbook = new ExcelJS.stream.xlsx.WorkbookWriter({
        stream: res,
        useStyles: true,
        useSharedStrings: false,
      });
      const sheet = workbook.addWorksheet('Clientes');
      sheet.columns = COLUMNS;
      sheet.getRow(1).font = { bold: true };
      sheet.views = [{ state: 'frozen', ySplit: 1 }];

      const query = new QueryStream(
        `SELECT id, name, document, email, phone, address, city, state, zip_code, created_at
           FROM customers
          WHERE company_id = $1
          ORDER BY name ASC
          LIMIT $2`,
        [companyId, MAX_EXPORT_ROWS],
        { batchSize: 500 }
      );
      const dbStream = client.query(query);

      // Cliente cancelou o download: interrompe a consulta e libera a conexão
      res.on('close', () => {
        if (!res.writableEnded) dbStream.destroy();
      });
      dbStream.on('close', () => release());

      let exported = 0;
      for await (const row of dbStream) {
        sheet.addRow(COLUMNS.reduce((acc, c) => {
          acc[c.key] = toCell(row[c.key]);
          return acc;
        }, {})).commit();
        exported += 1;
      }

      sheet.commit();
      await workbook.commit();

      // Trilha de auditoria (não bloqueia a resposta em caso de falha)
      pool
        .query(
          `INSERT INTO audit_logs (company_id, user_id, action, details, ip, created_at)
           VALUES ($1, $2, 'customers.export', $3, $4, NOW())`,
          [companyId, userId, JSON.stringify({ rows: exported }), req.ip]
        )
        .catch((e) => console.error('Falha ao registrar auditoria:', e.message));
    } catch (err) {
      release(err);
      if (res.headersSent) {
        // Já começou a enviar o arquivo: não dá para trocar o status; aborta a conexão
        console.error('Erro durante exportação:', err);
        return res.destroy(err);
      }
      return next(err);
    }
  }
);

module.exports = router;

/* Registro no app principal:
 *
 *   app.set('trust proxy', 1); // se estiver atrás de proxy/load balancer
 *   app.use('/api', require('./routes/clientes.export'));
 */