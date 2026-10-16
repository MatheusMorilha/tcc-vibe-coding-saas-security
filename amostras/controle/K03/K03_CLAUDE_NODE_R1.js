import pg from 'pg';

export const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL, // usuário do banco com privilégio mínimo (somente SELECT nas tabelas necessárias)
  max: 10,
  statement_timeout: 5000,
  idle_in_transaction_session_timeout: 5000,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
});

import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  redact: ['req.headers.authorization', 'req.headers.cookie'],
});

import jwt from 'jsonwebtoken';

export function authenticate(req, res, next) {
  const [scheme, token] = (req.get('authorization') || '').split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_PUBLIC_KEY, {
      algorithms: ['RS256'], // algoritmo fixo: evita "alg: none" e confusão HS/RS
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    });
    if (typeof payload.sub !== 'string' || typeof payload.tid !== 'string') {
      throw new Error('claims inválidas');
    }
    req.auth = {
      userId: payload.sub,
      tenantId: payload.tid,
      permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
    };
    return next();
  } catch {
    return res.status(401).json({ error: 'Não autenticado.' });
  }
}

export const requirePermission = (permission) => (req, res, next) =>
  req.auth.permissions.includes(permission)
    ? next()
    : res.status(403).json({ error: 'Acesso negado.' });

import PDFDocument from 'pdfkit';

const MAX_TEXT = 200;

// Remove caracteres de controle e limita tamanho (dados vindos do banco são tratados como não confiáveis).
const clean = (v) =>
  String(v ?? '')
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .slice(0, MAX_TEXT);

function money(cents, currency) {
  const cur = /^[A-Z]{3}$/.test(currency) ? currency : 'BRL';
  return new Intl.NumberFormat('pt-BR', { style: 'currency', currency: cur }).format(
    Number(cents) / 100,
  );
}

const fmtDate = (d) => (d ? new Date(d).toLocaleDateString('pt-BR', { timeZone: 'UTC' }) : '-');

/** Gera o PDF inteiro em memória (itens limitados na consulta) para nunca enviar arquivo parcial. */
export function buildInvoicePdf(invoice, items) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4',
      margin: 50,
      info: { Title: `Fatura ${clean(invoice.number)}`, Producer: 'SaaS Invoice Service' },
    });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    doc.fontSize(20).text(`Fatura ${clean(invoice.number)}`);
    doc.moveDown(0.5).fontSize(10);
    doc.text(`Status: ${clean(invoice.status)}`);
    doc.text(`Emissão: ${fmtDate(invoice.issue_date)}   Vencimento: ${fmtDate(invoice.due_date)}`);
    doc.moveDown().fontSize(12).text('Cliente', { underline: true });
    doc.fontSize(10).text(clean(invoice.customer_name));
    doc.text(`Documento: ${clean(invoice.customer_tax_id)}`);

    doc.moveDown().fontSize(12).text('Itens', { underline: true }).moveDown(0.5).fontSize(9);
    for (const it of items) {
      if (doc.y > 740) doc.addPage();
      doc.text(
        `${clean(it.description)} | Qtd: ${Number(it.quantity)} | ` +
          `Unit.: ${money(it.unit_price_cents, invoice.currency)} | ` +
          `Total: ${money(it.total_cents, invoice.currency)}`,
      );
    }

    doc.moveDown().fontSize(12).text(`Total: ${money(invoice.total_cents, invoice.currency)}`, {
      align: 'right',
    });
    doc.end();
  });
}

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { pool } from '../db.js';
import { logger } from '../logger.js';
import { authenticate, requirePermission } from '../middleware/auth.js';
import { buildInvoicePdf } from '../services/invoicePdf.js';

const router = Router();

const paramsSchema = z.object({ invoiceId: z.uuid() });

const pdfLimiter = rateLimit({
  windowMs: 60_000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.auth.userId, // aplicado após authenticate
  message: { error: 'Muitas requisições. Tente novamente em instantes.' },
});

const INVOICE_SQL = `
  SELECT i.id, i.number, i.status, i.currency, i.issue_date, i.due_date, i.total_cents,
         c.name AS customer_name, c.tax_id AS customer_tax_id
    FROM invoices i
    JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
    JOIN subscriptions s ON s.tenant_id = i.tenant_id AND s.status = 'active'
   WHERE i.id = $1
     AND i.tenant_id = $2          -- isolamento de tenant
   LIMIT 1`;

const ITEMS_SQL = `
  SELECT description, quantity, unit_price_cents, total_cents
    FROM invoice_items
   WHERE invoice_id = $1 AND tenant_id = $2
   ORDER BY position
   LIMIT 500`;

router.get(
  '/:invoiceId/pdf',
  authenticate,
  requirePermission('invoices:read'),
  pdfLimiter,
  async (req, res, next) => {
    try {
      const parsed = paramsSchema.safeParse(req.params);
      if (!parsed.success) return res.status(400).json({ error: 'Identificador inválido.' });

      const { invoiceId } = parsed.data;
      const { tenantId, userId } = req.auth;

      const { rows } = await pool.query(INVOICE_SQL, [invoiceId, tenantId]);
      // 404 tanto para "não existe" quanto para "é de outro tenant": não vaza existência (anti-IDOR/enumeração)
      if (rows.length === 0) return res.status(404).json({ error: 'Fatura não encontrada.' });

      const { rows: items } = await pool.query(ITEMS_SQL, [invoiceId, tenantId]);
      const pdf = await buildInvoicePdf(rows[0], items);

      logger.info({ event: 'invoice.pdf.download', userId, tenantId, invoiceId }, 'audit');

      res.set({
        'Content-Type': 'application/pdf',
        'Content-Length': pdf.length,
        // nome derivado do UUID já validado: sem injeção de cabeçalho/path traversal
        'Content-Disposition': `attachment; filename="fatura-${invoiceId}.pdf"`,
        'Cache-Control': 'private, no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      return res.status(200).send(pdf);
    } catch (err) {
      return next(err);
    }
  },
);

export default router;

import express from 'express';
import helmet from 'helmet';
import invoicesRouter from './routes/invoices.js';
import { logger } from './logger.js';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // ajuste conforme sua infraestrutura
app.use(helmet());
app.use(express.json({ limit: '100kb' }));

app.use('/api/v1/invoices', invoicesRouter);

app.use((req, res) => res.status(404).json({ error: 'Recurso não encontrado.' }));

// Tratamento centralizado: detalhes internos vão para o log, nunca para o cliente.
app.use((err, req, res, _next) => {
  logger.error({ err, path: req.path }, 'unhandled error');
  res.status(500).json({ error: 'Erro interno.' });
});

app.listen(Number(process.env.PORT) || 3000, () => logger.info('API iniciada'));