// src/routes/clientes.export.js
import { Router } from 'express';
import ExcelJS from 'exceljs';
import Cursor from 'pg-cursor';
import rateLimit from 'express-rate-limit';
import { pool } from '../db/pool.js';
import { authenticate, requirePermission } from '../middlewares/auth.js';
import { auditLog } from '../services/audit.js';

/**
 * Premissas (ajuste aos nomes reais do seu projeto):
 *  - `authenticate` valida o token/sessão e popula `req.auth = { userId, tenantId, role }`
 *    a partir do que foi VALIDADO no servidor (nunca de body/query/params).
 *  - `requirePermission('clientes:export')` verifica a permissão do usuário no tenant.
 *  - Tabelas: `clientes` (com `tenant_id`, `deleted_at`),
 *    `assinaturas` (tenant_id, status, plano_id) e `planos` (id, recursos jsonb).
 */

const router = Router();

const BATCH_SIZE = 1000;
const MAX_ROWS = 200_000; // teto de segurança por exportação

const COLUMNS = [
  { key: 'id', header: 'ID', width: 38 },
  { key: 'nome', header: 'Nome / Razão social', width: 40 },
  { key: 'documento', header: 'CPF/CNPJ', width: 20 },
  { key: 'email', header: 'E-mail', width: 36 },
  { key: 'telefone', header: 'Telefone', width: 20 },
  { key: 'logradouro', header: 'Logradouro', width: 36 },
  { key: 'numero', header: 'Número', width: 10 },
  { key: 'cidade', header: 'Cidade', width: 24 },
  { key: 'uf', header: 'UF', width: 6 },
  { key: 'cep', header: 'CEP', width: 12 },
  { key: 'status', header: 'Status', width: 12 },
  { key: 'criado_em', header: 'Criado em', width: 20 },
];

// ---------------------------------------------------------------------------
// Utilitários
// ---------------------------------------------------------------------------

// Mitigação de CSV/Formula Injection (defesa em profundidade: a planilha pode
// ser reexportada para CSV ou aberta em ferramentas que avaliam fórmulas).
// Valores que parecem telefone/número (ex.: "+55 45 99999-0000") são preservados.
const FORMULA_START = /^[=+\-@\t\r]/;
const PHONE_LIKE = /^\+?[\d\s().-]+$/;

function sanitizeCell(value) {
  if (typeof value !== 'string') return value;
  if (FORMULA_START.test(value) && !PHONE_LIKE.test(value)) return `'${value}`;
  return value;
}

const readBatch = (cursor, size) =>
  new Promise((resolve, reject) =>
    cursor.read(size, (err, rows) => (err ? reject(err) : resolve(rows)))
  );

const closeCursor = (cursor) =>
  new Promise((resolve) => cursor.close(() => resolve()));

// Verifica se o plano ativo do tenant inclui o recurso de exportação.
function requirePlanFeature(feature) {
  return async (req, res, next) => {
    try {
      const { rows } = await pool.query(
        `SELECT 1
           FROM assinaturas a
           JOIN planos p ON p.id = a.plano_id
          WHERE a.tenant_id = $1
            AND a.status = 'ativa'
            AND (p.recursos ->> $2)::boolean IS TRUE
          LIMIT 1`,
        [req.auth.tenantId, feature]
      );
      if (rows.length === 0) {
        return res.status(403).json({
          error: 'PLAN_FEATURE_UNAVAILABLE',
          message: 'O plano atual da empresa não inclui exportação de dados.',
        });
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

// Limite por empresa (e não por IP): exportações são operações pesadas.
const exportLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `export:${req.auth.tenantId}`,
  message: { error: 'RATE_LIMITED', message: 'Muitas exportações. Tente novamente em alguns minutos.' },
});

// ---------------------------------------------------------------------------
// Rota: GET /api/clientes/export
// ---------------------------------------------------------------------------

router.get(
  '/clientes/export',
  authenticate,
  requirePermission('clientes:export'),
  requirePlanFeature('exportacao_dados'),
  exportLimiter,
  async (req, res, next) => {
    // Dados confiáveis, vindos exclusivamente da sessão autenticada.
    const { tenantId, userId } = req.auth;

    let client;
    let cursor;
    let aborted = false;

    // Cliente fechou a conexão antes do término: interrompe a leitura.
    res.on('close', () => {
      if (!res.writableEnded) aborted = true;
    });

    try {
      client = await pool.connect();

      // O filtro por tenant_id é obrigatório em TODA consulta.
      cursor = client.query(
        new Cursor(
          `SELECT id, nome, documento, email, telefone,
                  logradouro, numero, cidade, uf, cep, status, criado_em
             FROM clientes
            WHERE tenant_id = $1
              AND deleted_at IS NULL
            ORDER BY nome ASC, id ASC
            LIMIT $2`,
          [tenantId, MAX_ROWS]
        )
      );

      const filename = `clientes_${new Date().toISOString().slice(0, 10)}.xlsx`;

      res.status(200);
      res.setHeader(
        'Content-Type',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      );
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');

      // Escrita em streaming: memória constante, independente do volume de dados.
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
      sheet.columns = COLUMNS.map(({ key, width }) => ({ key, width }));

      const headerRow = sheet.addRow(COLUMNS.map((c) => c.header));
      headerRow.font = { bold: true };
      headerRow.commit();

      let total = 0;
      for (;;) {
        if (aborted) break;
        const rows = await readBatch(cursor, BATCH_SIZE);
        if (rows.length === 0) break;

        for (const r of rows) {
          const out = {};
          for (const { key } of COLUMNS) out[key] = sanitizeCell(r[key]);
          sheet.addRow(out).commit();
        }
        total += rows.length;
      }

      if (aborted) return; // conexão já encerrada pelo cliente

      await sheet.commit();
      await workbook.commit(); // finaliza o arquivo e encerra a resposta

      // Trilha de auditoria (LGPD): quem exportou, quando e quantos registros.
      await auditLog({
        tenantId,
        userId,
        action: 'clientes.export',
        metadata: { rows: total, ip: req.ip, userAgent: req.get('user-agent') },
      }).catch((e) => console.error('Falha ao registrar auditoria', e));
    } catch (err) {
      console.error('Erro na exportação de clientes', { tenantId, err });
      if (!res.headersSent) return next(err);
      // Cabeçalhos já enviados: não há como trocar o status; aborta a conexão
      // para que o download falhe em vez de entregar um arquivo corrompido.
      res.destroy(err);
    } finally {
      if (cursor) await closeCursor(cursor).catch(() => {});
      if (client) client.release();
    }
  }
);

export default router;