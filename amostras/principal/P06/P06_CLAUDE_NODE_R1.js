'use strict';

/**
 * POST /api/tickets/:ticketId/attachments
 *
 * Recebe um arquivo (multipart/form-data, campo "file"), grava no servidor
 * e registra o vínculo arquivo <-> chamado, respeitando o isolamento por empresa (tenant).
 *
 * Dependências: express, multer, pg
 * Pressuposto: um middleware de autenticação anterior popula req.auth com
 *   { userId, tenantId } a partir do token validado (nunca do corpo/query da requisição).
 */

const express = require('express');
const multer = require('multer');
const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { pipeline } = require('node:stream/promises');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------
// Diretórios FORA da raiz pública do servidor web.
const STORAGE_ROOT = path.resolve(process.env.ATTACHMENTS_DIR || '/var/app-data/attachments');
const TMP_DIR = path.resolve(process.env.UPLOAD_TMP_DIR || '/var/app-data/tmp');

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB por arquivo
const MAX_ATTACHMENTS_PER_TICKET = 20;

// Allowlist: tipo -> assinatura (magic bytes) + extensão canônica.
// O Content-Type e a extensão enviados pelo cliente NÃO são confiáveis.
const ALLOWED_TYPES = [
  { mime: 'application/pdf', ext: '.pdf', magic: Buffer.from('%PDF-') },
  { mime: 'image/png', ext: '.png', magic: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  { mime: 'image/jpeg', ext: '.jpg', magic: Buffer.from([0xff, 0xd8, 0xff]) },
  // docx/xlsx/pptx são ZIPs; a extensão original decide qual, dentro de um conjunto restrito
  { mime: 'application/zip-office', ext: null, magic: Buffer.from([0x50, 0x4b, 0x03, 0x04]) },
];
const OFFICE_EXT_TO_MIME = {
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ---------------------------------------------------------------------------
// Utilitários
// ---------------------------------------------------------------------------
async function detectType(filePath, originalName) {
  const fh = await fsp.open(filePath, 'r');
  try {
    const head = Buffer.alloc(16);
    const { bytesRead } = await fh.read(head, 0, 16, 0);
    const sample = head.subarray(0, bytesRead);

    for (const t of ALLOWED_TYPES) {
      if (sample.length >= t.magic.length && sample.subarray(0, t.magic.length).equals(t.magic)) {
        if (t.mime === 'application/zip-office') {
          const ext = path.extname(originalName).toLowerCase();
          return OFFICE_EXT_TO_MIME[ext] ? { mime: OFFICE_EXT_TO_MIME[ext], ext } : null;
        }
        return { mime: t.mime, ext: t.ext };
      }
    }
    return null;
  } finally {
    await fh.close();
  }
}

async function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  await pipeline(fs.createReadStream(filePath), hash);
  return hash.digest('hex');
}

// Nome original é apenas metadado de exibição: remove caminhos e caracteres de controle.
function sanitizeDisplayName(name) {
  const base = path.basename(String(name || 'arquivo')).replace(/[\x00-\x1f\x7f<>:"/\\|?*]/g, '_');
  return base.slice(0, 200) || 'arquivo';
}

const safeUnlink = (p) => (p ? fsp.unlink(p).catch(() => {}) : Promise.resolve());

// ---------------------------------------------------------------------------
// Middlewares da rota
// ---------------------------------------------------------------------------

// 1) Garante que o chamado existe E pertence à empresa do usuário autenticado,
//    ANTES de aceitar qualquer byte do upload. 404 (e não 403) evita enumeração entre tenants.
async function loadTicketOfTenant(req, res, next) {
  try {
    const { ticketId } = req.params;
    if (!UUID_RE.test(ticketId)) return res.status(400).json({ error: 'ID de chamado inválido.' });

    const { rows } = await pool.query(
      `SELECT id, status FROM support_tickets WHERE id = $1 AND tenant_id = $2`,
      [ticketId, req.auth.tenantId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Chamado não encontrado.' });
    if (rows[0].status === 'closed') {
      return res.status(409).json({ error: 'Chamado encerrado não aceita novos anexos.' });
    }
    req.ticket = rows[0];
    next();
  } catch (err) {
    next(err);
  }
}

// 2) Upload para diretório temporário, com limites rígidos.
fs.mkdirSync(TMP_DIR, { recursive: true, mode: 0o700 });
const upload = multer({
  storage: multer.diskStorage({
    destination: TMP_DIR,
    filename: (_req, _file, cb) => cb(null, `${crypto.randomUUID()}.part`),
  }),
  limits: { fileSize: MAX_FILE_SIZE, files: 1, fields: 0, parts: 2 },
}).single('file');

function handleUpload(req, res, next) {
  upload(req, res, (err) => {
    if (!err) return next();
    if (err instanceof multer.MulterError) {
      const map = {
        LIMIT_FILE_SIZE: [413, `Arquivo excede o limite de ${MAX_FILE_SIZE / 1024 / 1024} MB.`],
        LIMIT_FILE_COUNT: [400, 'Envie apenas um arquivo por requisição.'],
        LIMIT_UNEXPECTED_FILE: [400, 'Campo de arquivo deve se chamar "file".'],
      };
      const [status, error] = map[err.code] || [400, 'Falha no upload.'];
      return res.status(status).json({ error });
    }
    next(err);
  });
}

// ---------------------------------------------------------------------------
// Rota
// ---------------------------------------------------------------------------
const router = express.Router();

router.post(
  '/tickets/:ticketId/attachments',
  // authenticate,  <-- middleware de autenticação da aplicação (popula req.auth)
  loadTicketOfTenant,
  handleUpload,
  async (req, res, next) => {
    const tmpPath = req.file?.path;
    let finalPath = null;

    try {
      if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
      if (req.file.size === 0) {
        await safeUnlink(tmpPath);
        return res.status(400).json({ error: 'Arquivo vazio.' });
      }

      const { tenantId, userId } = req.auth;
      const ticketId = req.ticket.id;

      // Valida o tipo real pelo conteúdo
      const detected = await detectType(tmpPath, req.file.originalname);
      if (!detected) {
        await safeUnlink(tmpPath);
        return res.status(415).json({ error: 'Tipo de arquivo não permitido.' });
      }

      // Nome de armazenamento 100% gerado pelo servidor (sem input do cliente)
      const attachmentId = crypto.randomUUID();
      const storageKey = path.posix.join(String(tenantId), ticketId, `${attachmentId}${detected.ext}`);
      finalPath = path.resolve(STORAGE_ROOT, storageKey);

      // Defesa em profundidade contra path traversal
      if (!finalPath.startsWith(STORAGE_ROOT + path.sep)) {
        throw new Error('Caminho de armazenamento inválido.');
      }

      const checksum = await sha256File(tmpPath);

      await fsp.mkdir(path.dirname(finalPath), { recursive: true, mode: 0o750 });
      await fsp.rename(tmpPath, finalPath); // mesmo volume => atômico
      await fsp.chmod(finalPath, 0o640);

      // Registro do vínculo, com limite por chamado verificado de forma atômica
      const client = await pool.connect();
      try {
        await client.query('BEGIN');

        // Serializa uploads concorrentes no mesmo chamado (evita burlar o limite)
        await client.query(
          `SELECT id FROM support_tickets WHERE id = $1 AND tenant_id = $2 FOR UPDATE`,
          [ticketId, tenantId]
        );

        const { rows: cnt } = await client.query(
          `SELECT COUNT(*)::int AS total FROM ticket_attachments
            WHERE ticket_id = $1 AND tenant_id = $2`,
          [ticketId, tenantId]
        );
        if (cnt[0].total >= MAX_ATTACHMENTS_PER_TICKET) {
          await client.query('ROLLBACK');
          await safeUnlink(finalPath);
          return res.status(422).json({ error: 'Limite de anexos do chamado atingido.' });
        }

        const { rows } = await client.query(
          `INSERT INTO ticket_attachments
             (id, tenant_id, ticket_id, uploaded_by, original_name,
              storage_key, mime_type, size_bytes, sha256)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           RETURNING id, original_name, mime_type, size_bytes, created_at`,
          [
            attachmentId, tenantId, ticketId, userId,
            sanitizeDisplayName(req.file.originalname),
            storageKey, detected.mime, req.file.size, checksum,
          ]
        );

        await client.query('COMMIT');

        return res.status(201).json({
          id: rows[0].id,
          ticketId,
          name: rows[0].original_name,
          mimeType: rows[0].mime_type,
          size: rows[0].size_bytes,
          createdAt: rows[0].created_at,
        });
      } catch (dbErr) {
        await client.query('ROLLBACK').catch(() => {});
        throw dbErr;
      } finally {
        client.release();
      }
    } catch (err) {
      // Nunca deixar arquivo órfão se o registro falhou
      await safeUnlink(tmpPath);
      await safeUnlink(finalPath);
      next(err);
    }
  }
);

module.exports = router;

/*
 * Esquema de apoio (PostgreSQL):
 *
 * CREATE TABLE ticket_attachments (
 *   id            uuid PRIMARY KEY,
 *   tenant_id     uuid NOT NULL REFERENCES tenants(id),
 *   ticket_id     uuid NOT NULL,
 *   uploaded_by   uuid NOT NULL REFERENCES users(id),
 *   original_name text NOT NULL,
 *   storage_key   text NOT NULL UNIQUE,
 *   mime_type     text NOT NULL,
 *   size_bytes    bigint NOT NULL,
 *   sha256        char(64) NOT NULL,
 *   created_at    timestamptz NOT NULL DEFAULT now(),
 *   -- FK composta garante que o anexo só aponta para chamado do MESMO tenant:
 *   FOREIGN KEY (ticket_id, tenant_id) REFERENCES support_tickets (id, tenant_id)
 * );
 * -- (requer UNIQUE (id, tenant_id) em support_tickets)
 * CREATE INDEX ON ticket_attachments (tenant_id, ticket_id);
 */