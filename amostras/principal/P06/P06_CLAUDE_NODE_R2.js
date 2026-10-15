// routes/ticketAttachments.js
'use strict';

const express = require('express');
const multer = require('multer');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs/promises');
const { pool } = require('../db'); // instância pg.Pool

const router = express.Router();

// ---------- Configuração ----------
const STORAGE_ROOT = process.env.ATTACHMENTS_DIR || '/var/app-data/attachments'; // fora do webroot
const TMP_DIR = path.join(STORAGE_ROOT, '_tmp');
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

// Allowlist: extensão -> MIME real (validado pelos magic bytes)
const ALLOWED = new Map([
  ['.pdf',  'application/pdf'],
  ['.png',  'image/png'],
  ['.jpg',  'image/jpeg'],
  ['.jpeg', 'image/jpeg'],
  ['.webp', 'image/webp'],
  ['.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  ['.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ---------- Multer: grava em diretório temporário com nome aleatório ----------
const upload = multer({
  storage: multer.diskStorage({
    destination: async (req, file, cb) => {
      try {
        await fs.mkdir(TMP_DIR, { recursive: true, mode: 0o700 });
        cb(null, TMP_DIR);
      } catch (err) { cb(err); }
    },
    filename: (req, file, cb) => cb(null, crypto.randomUUID()), // nunca usa o nome do cliente
  }),
  limits: { fileSize: MAX_FILE_SIZE, files: 1, fields: 0 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED.has(ext)) {
      return cb(Object.assign(new Error('Tipo de arquivo não permitido.'), { status: 415 }));
    }
    cb(null, true);
  },
});

// ---------- Middlewares ----------

// Autoriza o acesso ao chamado ANTES de aceitar qualquer byte do upload.
async function authorizeTicket(req, res, next) {
  try {
    const { ticketId } = req.params;
    if (!UUID_RE.test(ticketId)) {
      return res.status(400).json({ error: 'Identificador de chamado inválido.' });
    }

    // Isolamento multilocatário: o chamado precisa pertencer ao tenant do usuário autenticado.
    const { rows } = await pool.query(
      `SELECT id, status, created_by
         FROM support_tickets
        WHERE id = $1 AND tenant_id = $2`,
      [ticketId, req.user.tenantId]
    );

    // 404 (e não 403) para não revelar a existência de chamados de outros tenants.
    if (rows.length === 0) return res.status(404).json({ error: 'Chamado não encontrado.' });
    if (rows[0].status === 'closed') {
      return res.status(409).json({ error: 'Chamado encerrado não aceita novos anexos.' });
    }

    req.ticket = rows[0];
    next();
  } catch (err) { next(err); }
}

// ---------- Rota ----------
router.post(
  '/tickets/:ticketId/attachments',
  authorizeTicket,
  upload.single('file'),
  async (req, res, next) => {
    const tmpFile = req.file;
    let finalPath = null;
    let client = null;

    try {
      if (!tmpFile) return res.status(400).json({ error: 'Nenhum arquivo enviado (campo "file").' });

      const { id: userId, tenantId } = req.user;
      const { ticketId } = req.params;

      // 1) Valida o conteúdo real (magic bytes), não apenas extensão/Content-Type do cliente.
      const { fileTypeFromFile } = await import('file-type'); // pacote ESM
      const detected = await fileTypeFromFile(tmpFile.path);
      const ext = path.extname(tmpFile.originalname).toLowerCase();
      if (!detected || detected.mime !== ALLOWED.get(ext)) {
        throw Object.assign(new Error('O conteúdo do arquivo não corresponde ao tipo declarado.'), { status: 415 });
      }

      // 2) Move para o diretório definitivo, segregado por tenant/chamado.
      const attachmentId = crypto.randomUUID();
      const storageKey = path.posix.join(tenantId, ticketId, `${attachmentId}${ext}`);
      finalPath = path.resolve(STORAGE_ROOT, storageKey);

      // Defesa em profundidade contra path traversal.
      if (!finalPath.startsWith(path.resolve(STORAGE_ROOT) + path.sep)) {
        throw new Error('Caminho de armazenamento inválido.');
      }
      await fs.mkdir(path.dirname(finalPath), { recursive: true, mode: 0o700 });
      await fs.rename(tmpFile.path, finalPath);
      await fs.chmod(finalPath, 0o640);

      // 3) Registra o vínculo em transação, com verificação de cota do plano.
      const originalName = path.basename(tmpFile.originalname).replace(/[^\w.\- ()]/g, '_').slice(0, 255);
      const checksum = await sha256File(finalPath);

      client = await pool.connect();
      await client.query('BEGIN');

      // Serializa uploads do mesmo tenant para a checagem de cota não sofrer race condition.
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [tenantId]);

      const { rows: quota } = await client.query(
        `SELECT p.storage_limit_bytes AS "limit",
                COALESCE((SELECT SUM(size_bytes) FROM ticket_attachments WHERE tenant_id = $1), 0) AS used
           FROM tenants t
           JOIN subscription_plans p ON p.id = t.plan_id
          WHERE t.id = $1 AND t.subscription_status = 'active'`,
        [tenantId]
      );
      if (quota.length === 0) {
        throw Object.assign(new Error('Assinatura inativa.'), { status: 402 });
      }
      if (Number(quota[0].used) + tmpFile.size > Number(quota[0].limit)) {
        throw Object.assign(new Error('Limite de armazenamento do plano excedido.'), { status: 413 });
      }

      const { rows } = await client.query(
        `INSERT INTO ticket_attachments
           (id, tenant_id, ticket_id, uploaded_by, original_name, storage_key, mime_type, size_bytes, sha256)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id, original_name, mime_type, size_bytes, created_at`,
        [attachmentId, tenantId, ticketId, userId, originalName, storageKey, detected.mime, tmpFile.size, checksum]
      );

      await client.query('COMMIT');
      return res.status(201).json({ attachment: rows[0] });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      // Não deixa arquivos órfãos em caso de falha.
      if (finalPath) await fs.rm(finalPath, { force: true }).catch(() => {});
      if (tmpFile) await fs.rm(tmpFile.path, { force: true }).catch(() => {});
      return next(err);
    } finally {
      if (client) client.release();
    }
  }
);

// ---------- Utilitário ----------
async function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  const handle = await fs.open(filePath, 'r');
  try {
    for await (const chunk of handle.createReadStream()) hash.update(chunk);
  } finally {
    await handle.close();
  }
  return hash.digest('hex');
}

// ---------- Tratamento de erros da rota ----------
router.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    const msg = err.code === 'LIMIT_FILE_SIZE'
      ? `Arquivo excede o limite de ${MAX_FILE_SIZE / 1024 / 1024} MB.`
      : 'Requisição de upload inválida.';
    return res.status(status).json({ error: msg });
  }
  if (err.status && err.status < 500) return res.status(err.status).json({ error: err.message });
  console.error('[ticket-attachments]', err); // log interno; resposta genérica ao cliente
  return res.status(500).json({ error: 'Erro interno ao processar o anexo.' });
});

module.exports = router;