'use strict';

/**
 * POST /api/v1/tickets/:ticketId/attachments
 *
 * Recebe um arquivo (multipart/form-data, campo "file"), grava no servidor e
 * registra o vínculo arquivo <-> chamado, respeitando o isolamento entre tenants.
 *
 * Dependências: express, multer, pg, express-rate-limit
 *   npm i express multer pg express-rate-limit
 *
 * Pré-requisitos (feitos por middlewares anteriores, fora desta rota):
 *   - req.auth = { userId, tenantId, role }  -> vem do JWT/sessão VALIDADO.
 *     O tenant NUNCA é lido de body, query, header ou path vindos do cliente.
 *   - req.db = Pool do pg (ou injete via factory, como abaixo).
 *
 * Esquema esperado (PostgreSQL):
 *
 *   CREATE TABLE ticket_attachments (
 *     id            UUID PRIMARY KEY,
 *     tenant_id     UUID NOT NULL REFERENCES tenants(id),
 *     ticket_id     UUID NOT NULL,
 *     uploaded_by   UUID NOT NULL REFERENCES users(id),
 *     original_name TEXT NOT NULL,          -- apenas para exibição
 *     stored_name   TEXT NOT NULL,          -- nome gerado pelo servidor
 *     storage_path  TEXT NOT NULL,          -- relativo à raiz de storage
 *     mime_type     TEXT NOT NULL,          -- detectado pelo servidor
 *     size_bytes    BIGINT NOT NULL,
 *     sha256        CHAR(64) NOT NULL,
 *     created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
 *     FOREIGN KEY (ticket_id, tenant_id) REFERENCES tickets(id, tenant_id)
 *   );
 *   CREATE INDEX ON ticket_attachments (tenant_id, ticket_id);
 *
 *   -- planos: plans.max_attachment_bytes, plans.storage_quota_bytes,
 *   --         plans.max_attachments_per_ticket ; tenants.plan_id, tenants.subscription_status
 */

const express = require('express');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------

// Raiz de armazenamento FORA de qualquer diretório servido estaticamente.
const STORAGE_ROOT = path.resolve(process.env.ATTACHMENTS_DIR || '/var/app-data/attachments');
const TMP_DIR = path.join(os.tmpdir(), 'upload-tmp');

// Teto rígido do processo (o limite do plano é sempre <= este valor).
const HARD_MAX_FILE_BYTES = 25 * 1024 * 1024;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Allowlist por conteúdo real (magic bytes). O Content-Type e a extensão
// enviados pelo cliente NÃO são confiáveis e não definem nada aqui.
const ALLOWED_TYPES = [
  { mime: 'application/pdf', ext: '.pdf', test: (b) => b.subarray(0, 5).toString('latin1') === '%PDF-' },
  { mime: 'image/png', ext: '.png', test: (b) => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) },
  { mime: 'image/jpeg', ext: '.jpg', test: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { mime: 'image/gif', ext: '.gif', test: (b) => ['GIF87a', 'GIF89a'].includes(b.subarray(0, 6).toString('latin1')) },
  {
    mime: 'image/webp',
    ext: '.webp',
    test: (b) => b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP',
  },
];

// ---------------------------------------------------------------------------
// Utilitários
// ---------------------------------------------------------------------------

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function readHead(filePath, length = 16) {
  const fh = await fsp.open(filePath, 'r');
  try {
    const buf = Buffer.alloc(length);
    const { bytesRead } = await fh.read(buf, 0, length, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    fs.createReadStream(filePath)
      .on('error', reject)
      .on('data', (c) => hash.update(c))
      .on('end', () => resolve(hash.digest('hex')));
  });
}

// Nome original só serve para exibição: remove caminho, controles e limita tamanho.
function sanitizeDisplayName(name) {
  const base = path.basename(String(name || 'arquivo')).normalize('NFC');
  const cleaned = base.replace(/[\u0000-\u001f\u007f<>:"/\\|?*]/g, '_').trim();
  return (cleaned || 'arquivo').slice(0, 180);
}

async function safeUnlink(p) {
  if (!p) return;
  try {
    await fsp.unlink(p);
  } catch (e) {
    if (e.code !== 'ENOENT') console.error('[attachments] falha ao remover arquivo órfão', e.message);
  }
}

// Garante que o caminho final está dentro da raiz de storage.
function resolveInsideRoot(...segments) {
  const full = path.resolve(STORAGE_ROOT, ...segments);
  if (full !== STORAGE_ROOT && !full.startsWith(STORAGE_ROOT + path.sep)) {
    throw new HttpError(500, 'PATH_ESCAPE', 'Caminho de armazenamento inválido.');
  }
  return full;
}

// ---------------------------------------------------------------------------
// Upload para diretório temporário (nome 100% gerado pelo servidor)
// ---------------------------------------------------------------------------

fs.mkdirSync(TMP_DIR, { recursive: true, mode: 0o700 });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, TMP_DIR),
    filename: (_req, _file, cb) => cb(null, `${crypto.randomUUID()}.part`),
  }),
  limits: {
    fileSize: HARD_MAX_FILE_BYTES,
    files: 1,
    fields: 0,
    parts: 2,
  },
}).single('file');

function handleUpload(req, res, next) {
  upload(req, res, (err) => {
    if (!err) return next();
    if (err instanceof multer.MulterError) {
      const map = {
        LIMIT_FILE_SIZE: [413, 'FILE_TOO_LARGE', 'Arquivo excede o tamanho máximo permitido.'],
        LIMIT_UNEXPECTED_FILE: [400, 'UNEXPECTED_FIELD', 'Envie apenas um arquivo no campo "file".'],
        LIMIT_FILE_COUNT: [400, 'TOO_MANY_FILES', 'Envie apenas um arquivo por requisição.'],
      };
      const [status, code, msg] = map[err.code] || [400, 'UPLOAD_ERROR', 'Falha no envio do arquivo.'];
      return next(new HttpError(status, code, msg));
    }
    return next(err);
  });
}

// ---------------------------------------------------------------------------
// Fábrica da rota
// ---------------------------------------------------------------------------

function createTicketAttachmentsRouter({ pool, requireAuth }) {
  const router = express.Router();

  const limiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 20,
    // limita por tenant+usuário, não só por IP
    keyGenerator: (req) => `${req.auth?.tenantId}:${req.auth?.userId}`,
    standardHeaders: true,
    legacyHeaders: false,
  });

  router.post(
    '/tickets/:ticketId/attachments',
    requireAuth, // popula req.auth a partir de credencial validada
    limiter,
    handleUpload,
    async (req, res, next) => {
      const tmpPath = req.file?.path;
      let finalPath = null;
      let client = null;

      try {
        // ---- 1. Entrada -----------------------------------------------------
        const { tenantId, userId } = req.auth || {};
        if (!tenantId || !userId) throw new HttpError(401, 'UNAUTHENTICATED', 'Não autenticado.');

        const { ticketId } = req.params;
        if (!UUID_RE.test(ticketId)) throw new HttpError(400, 'INVALID_TICKET_ID', 'Identificador de chamado inválido.');
        if (!req.file) throw new HttpError(400, 'NO_FILE', 'Nenhum arquivo enviado.');
        if (req.file.size === 0) throw new HttpError(400, 'EMPTY_FILE', 'O arquivo está vazio.');

        // ---- 2. Tipo real do arquivo (magic bytes) -------------------------
        const head = await readHead(tmpPath, 16);
        const detected = ALLOWED_TYPES.find((t) => t.test(head));
        if (!detected) {
          throw new HttpError(415, 'UNSUPPORTED_TYPE', 'Tipo de arquivo não permitido. Aceitos: PDF, PNG, JPEG, GIF e WebP.');
        }

        const sha256 = await sha256File(tmpPath);
        const attachmentId = crypto.randomUUID();
        const storedName = `${attachmentId}${detected.ext}`;

        // Layout: <root>/<tenant>/<yyyy-mm>/<uuid.ext>
        // tenantId vem do token e já é validado como UUID abaixo.
        if (!UUID_RE.test(tenantId)) throw new HttpError(403, 'INVALID_TENANT', 'Tenant inválido.');
        const yearMonth = new Date().toISOString().slice(0, 7);
        const relPath = path.join(tenantId, yearMonth, storedName);
        finalPath = resolveInsideRoot(relPath);

        // ---- 3. Transação: autorização + plano + cota + vínculo ------------
        client = await pool.connect();
        await client.query('BEGIN');

        // Serializa uploads do mesmo tenant para a checagem de cota não sofrer corrida.
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`attach:${tenantId}`]);

        // 3a. Assinatura ativa e limites do plano
        const planRes = await client.query(
          `SELECT t.subscription_status,
                  p.max_attachment_bytes,
                  p.storage_quota_bytes,
                  p.max_attachments_per_ticket
             FROM tenants t
             JOIN plans p ON p.id = t.plan_id
            WHERE t.id = $1`,
          [tenantId]
        );
        const plan = planRes.rows[0];
        if (!plan) throw new HttpError(403, 'TENANT_NOT_FOUND', 'Empresa não encontrada.');
        if (!['active', 'trialing'].includes(plan.subscription_status)) {
          throw new HttpError(402, 'SUBSCRIPTION_INACTIVE', 'Assinatura inativa. Regularize para enviar anexos.');
        }

        const maxFile = Math.min(Number(plan.max_attachment_bytes), HARD_MAX_FILE_BYTES);
        if (req.file.size > maxFile) {
          throw new HttpError(413, 'PLAN_FILE_LIMIT', 'Arquivo excede o limite do seu plano.');
        }

        // 3b. O chamado existe NESTE tenant e o usuário pode anexar nele?
        //     Filtro por tenant_id obrigatório. Resposta idêntica para "não existe"
        //     e "é de outro tenant" (404) para não vazar a existência do recurso.
        const ticketRes = await client.query(
          `SELECT id, status, created_by, assigned_to
             FROM tickets
            WHERE id = $1 AND tenant_id = $2
            FOR SHARE`,
          [ticketId, tenantId]
        );
        const ticket = ticketRes.rows[0];
        if (!ticket) throw new HttpError(404, 'TICKET_NOT_FOUND', 'Chamado não encontrado.');

        const isStaff = ['admin', 'support'].includes(req.auth.role);
        const isParticipant = ticket.created_by === userId || ticket.assigned_to === userId;
        if (!isStaff && !isParticipant) {
          throw new HttpError(404, 'TICKET_NOT_FOUND', 'Chamado não encontrado.');
        }
        if (ticket.status === 'closed') {
          throw new HttpError(409, 'TICKET_CLOSED', 'Não é possível anexar arquivos a um chamado encerrado.');
        }

        // 3c. Cotas do plano
        const usageRes = await client.query(
          `SELECT COALESCE(SUM(size_bytes), 0)::bigint                       AS tenant_bytes,
                  COUNT(*) FILTER (WHERE ticket_id = $2)::int                AS ticket_count
             FROM ticket_attachments
            WHERE tenant_id = $1`,
          [tenantId, ticketId]
        );
        const usage = usageRes.rows[0];
        if (Number(usage.tenant_bytes) + req.file.size > Number(plan.storage_quota_bytes)) {
          throw new HttpError(402, 'STORAGE_QUOTA_EXCEEDED', 'Cota de armazenamento do plano excedida.');
        }
        if (usage.ticket_count >= plan.max_attachments_per_ticket) {
          throw new HttpError(409, 'TICKET_ATTACHMENT_LIMIT', 'Limite de anexos por chamado atingido.');
        }

        // 3d. Grava o arquivo (rename atômico) e só então registra o vínculo
        await fsp.mkdir(path.dirname(finalPath), { recursive: true, mode: 0o750 });
        try {
          await fsp.rename(tmpPath, finalPath);
        } catch (e) {
          if (e.code !== 'EXDEV') throw e;
          // tmp e storage em volumes diferentes
          await fsp.copyFile(tmpPath, finalPath, fs.constants.COPYFILE_EXCL);
          await safeUnlink(tmpPath);
        }
        await fsp.chmod(finalPath, 0o640);

        const insertRes = await client.query(
          `INSERT INTO ticket_attachments
             (id, tenant_id, ticket_id, uploaded_by, original_name, stored_name,
              storage_path, mime_type, size_bytes, sha256)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
           RETURNING id, ticket_id, original_name, mime_type, size_bytes, created_at`,
          [
            attachmentId,
            tenantId,
            ticketId,
            userId,
            sanitizeDisplayName(req.file.originalname),
            storedName,
            relPath,
            detected.mime,
            req.file.size,
            sha256,
          ]
        );

        await client.query(
          `INSERT INTO audit_log (tenant_id, user_id, action, entity, entity_id)
           VALUES ($1,$2,'ticket.attachment.created','ticket',$3)`,
          [tenantId, userId, ticketId]
        );

        await client.query('COMMIT');
        finalPath = null; // sucesso: não remover

        const row = insertRes.rows[0];
        return res.status(201).json({
          id: row.id,
          ticketId: row.ticket_id,
          name: row.original_name,
          mimeType: row.mime_type,
          sizeBytes: Number(row.size_bytes),
          createdAt: row.created_at,
        });
      } catch (err) {
        if (client) {
          try {
            await client.query('ROLLBACK');
          } catch (_) {
            /* conexão já pode ter caído */
          }
        }
        return next(err);
      } finally {
        if (client) client.release();
        // Limpeza: temporário não movido e arquivo final sem vínculo commitado.
        await safeUnlink(tmpPath);
        await safeUnlink(finalPath);
      }
    }
  );

  // Tratador de erros do router: não vaza detalhes internos.
  router.use((err, _req, res, _next) => {
    if (err instanceof HttpError) {
      return res.status(err.status).json({ error: { code: err.code, message: err.message } });
    }
    console.error('[attachments] erro inesperado:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Erro interno ao processar o anexo.' } });
  });

  return router;
}

module.exports = { createTicketAttachmentsRouter };

/* Exemplo de montagem:
 *
 *   const app = express();
 *   const { Pool } = require('pg');
 *   const pool = new Pool({ connectionString: process.env.DATABASE_URL });
 *   app.use('/api/v1', createTicketAttachmentsRouter({ pool, requireAuth }));
 */