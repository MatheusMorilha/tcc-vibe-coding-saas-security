'use strict';

/**
 * POST /api/customers/import
 * Importação em lote de clientes via planilha (.csv ou .xlsx).
 *
 * Dependências: express, multer, pg, csv-parse, exceljs
 *
 * Esquema esperado (PostgreSQL):
 *   tenants(id, plan_id, ...)
 *   plans(id, max_customers, ...)               -- max_customers NULL = ilimitado
 *   customers(id, tenant_id, name, email, document, phone, created_by, created_at,
 *             UNIQUE (tenant_id, email))
 *
 * Premissas de segurança (multilocatário):
 *   - req.auth é preenchido por um middleware de autenticação anterior
 *     ({ userId, tenantId, role }). O tenantId NUNCA vem da planilha/body.
 *   - Toda escrita carrega tenant_id; a unicidade é por (tenant_id, email),
 *     então um e-mail existente em outra empresa não conflita nem vaza.
 */

const express = require('express');
const multer = require('multer');
const { parse: parseCsv } = require('csv-parse/sync');
const ExcelJS = require('exceljs');
const { Pool } = require('pg');

const pool = new Pool(); // configuração via variáveis PG* / DATABASE_URL

// ---------------------------------------------------------------- limites
const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB
const MAX_ROWS = 5000; // linhas de dados por importação
const CHUNK_SIZE = 500; // linhas por INSERT
const MAX_ERRORS_IN_RESPONSE = 100; // evita resposta gigante
const ALLOWED_ROLES = new Set(['owner', 'admin', 'manager']);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_BYTES, files: 1 },
});

// ---------------------------------------------------------------- erros
class HttpError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

// ---------------------------------------------------------------- parsing
const HEADER_ALIASES = {
  name: ['nome', 'name', 'razao social', 'razao_social', 'cliente'],
  email: ['email', 'e-mail'],
  document: ['documento', 'cpf', 'cnpj', 'cpf/cnpj', 'cpf_cnpj', 'document'],
  phone: ['telefone', 'celular', 'fone', 'phone'],
};

const normalizeHeader = (h) =>
  String(h ?? '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim()
    .toLowerCase();

function buildHeaderMap(headers) {
  const map = {}; // campo canônico -> índice da coluna
  headers.forEach((h, idx) => {
    const norm = normalizeHeader(h);
    for (const [field, aliases] of Object.entries(HEADER_ALIASES)) {
      if (aliases.includes(norm) && map[field] === undefined) map[field] = idx;
    }
  });
  const missing = ['name', 'email'].filter((f) => map[f] === undefined);
  if (missing.length) {
    throw new HttpError(
      422,
      'INVALID_HEADERS',
      `Colunas obrigatórias ausentes: ${missing.join(', ')}.`
    );
  }
  return map;
}

function cellToString(value) {
  if (value == null) return '';
  if (typeof value === 'object') {
    if (value.text !== undefined) return String(value.text); // hyperlink
    if (Array.isArray(value.richText)) return value.richText.map((r) => r.text).join('');
    if (value.result !== undefined) return String(value.result); // fórmula
    if (value instanceof Date) return value.toISOString();
  }
  return String(value);
}

async function readRows(file) {
  const name = (file.originalname || '').toLowerCase();
  let matrix; // array de arrays de strings; linha 0 = cabeçalho

  if (name.endsWith('.csv')) {
    matrix = parseCsv(file.buffer, {
      bom: true,
      delimiter: [',', ';'], // planilhas BR costumam usar ';'
      skip_empty_lines: true,
      relax_column_count: true,
      trim: true,
    });
  } else if (name.endsWith('.xlsx')) {
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(file.buffer);
    const ws = wb.worksheets[0];
    if (!ws) throw new HttpError(422, 'EMPTY_FILE', 'A planilha não possui abas.');
    matrix = [];
    ws.eachRow({ includeEmpty: false }, (row) => {
      // row.values é 1-indexado
      matrix.push(row.values.slice(1).map(cellToString));
    });
  } else {
    throw new HttpError(415, 'UNSUPPORTED_FILE', 'Envie um arquivo .csv ou .xlsx.');
  }

  if (matrix.length < 2) {
    throw new HttpError(422, 'EMPTY_FILE', 'A planilha não contém registros.');
  }
  if (matrix.length - 1 > MAX_ROWS) {
    throw new HttpError(
      413,
      'TOO_MANY_ROWS',
      `Limite de ${MAX_ROWS} registros por importação excedido.`
    );
  }

  const headerMap = buildHeaderMap(matrix[0]);
  return matrix.slice(1).map((cells, i) => ({
    line: i + 2, // número da linha na planilha (cabeçalho = 1)
    name: (cells[headerMap.name] ?? '').toString().trim(),
    email: (cells[headerMap.email] ?? '').toString().trim().toLowerCase(),
    document: headerMap.document !== undefined ? String(cells[headerMap.document] ?? '') : '',
    phone: headerMap.phone !== undefined ? String(cells[headerMap.phone] ?? '') : '',
  }));
}

// ---------------------------------------------------------------- validação
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateRow(r) {
  const errors = [];
  if (!r.name) errors.push('nome é obrigatório');
  else if (r.name.length > 200) errors.push('nome excede 200 caracteres');

  if (!r.email) errors.push('e-mail é obrigatório');
  else if (r.email.length > 254 || !EMAIL_RE.test(r.email)) errors.push('e-mail inválido');

  const doc = r.document.replace(/\D/g, '');
  if (doc && doc.length !== 11 && doc.length !== 14) {
    errors.push('documento deve ter 11 (CPF) ou 14 (CNPJ) dígitos');
  }

  const phone = r.phone.replace(/[^\d+]/g, '');
  if (phone && (phone.length < 8 || phone.length > 16)) errors.push('telefone inválido');

  return {
    errors,
    clean: { name: r.name, email: r.email, document: doc || null, phone: phone || null },
  };
}

// ---------------------------------------------------------------- persistência
async function insertChunk(client, tenantId, userId, rows) {
  // unnest evita o limite de parâmetros do PostgreSQL e mantém a query parametrizada
  const { rows: inserted } = await client.query(
    `INSERT INTO customers (tenant_id, name, email, document, phone, created_by)
     SELECT $1, t.name, t.email, t.document, t.phone, $2
       FROM unnest($3::text[], $4::text[], $5::text[], $6::text[])
            AS t(name, email, document, phone)
     ON CONFLICT (tenant_id, email) DO NOTHING
     RETURNING id`,
    [
      tenantId,
      userId,
      rows.map((r) => r.name),
      rows.map((r) => r.email),
      rows.map((r) => r.document),
      rows.map((r) => r.phone),
    ]
  );
  return inserted.length;
}

async function persistCustomers(tenantId, userId, validRows) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Trava a linha do tenant: serializa importações concorrentes da mesma
    // empresa para que o limite do plano não seja ultrapassado por corrida.
    const { rows: planRows } = await client.query(
      `SELECT p.max_customers
         FROM tenants t
         JOIN plans p ON p.id = t.plan_id
        WHERE t.id = $1
        FOR UPDATE OF t`,
      [tenantId]
    );
    if (!planRows.length) {
      throw new HttpError(403, 'NO_ACTIVE_PLAN', 'Empresa sem plano de assinatura ativo.');
    }
    const maxCustomers = planRows[0].max_customers; // null = ilimitado

    let inserted = 0;
    for (let i = 0; i < validRows.length; i += CHUNK_SIZE) {
      inserted += await insertChunk(client, tenantId, userId, validRows.slice(i, i + CHUNK_SIZE));
    }

    if (maxCustomers !== null) {
      const { rows } = await client.query(
        'SELECT count(*)::int AS total FROM customers WHERE tenant_id = $1',
        [tenantId]
      );
      if (rows[0].total > maxCustomers) {
        // Estourou o limite: desfaz tudo (rollback no catch)
        throw new HttpError(
          403,
          'PLAN_LIMIT_EXCEEDED',
          `A importação excederia o limite do plano (${maxCustomers} clientes). ` +
            'Nenhum registro foi gravado.',
          { planLimit: maxCustomers, currentAfterImport: rows[0].total }
        );
      }
    }

    await client.query('COMMIT');
    return inserted;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// ---------------------------------------------------------------- rota
const router = express.Router();

router.post('/api/customers/import', upload.single('file'), async (req, res, next) => {
  try {
    // 1) Autorização e identificação do tenant (sempre da sessão)
    const auth = req.auth;
    if (!auth?.tenantId || !auth?.userId) {
      throw new HttpError(401, 'UNAUTHENTICATED', 'Não autenticado.');
    }
    if (!ALLOWED_ROLES.has(auth.role)) {
      throw new HttpError(403, 'FORBIDDEN', 'Sem permissão para importar clientes.');
    }
    if (!req.file) {
      throw new HttpError(400, 'FILE_REQUIRED', 'Envie o arquivo no campo "file".');
    }

    // 2) Leitura e validação linha a linha
    const rows = await readRows(req.file);

    const errors = [];
    const valid = [];
    const seenInFile = new Map(); // email -> primeira linha em que apareceu
    let duplicatesInFile = 0;

    for (const r of rows) {
      const { errors: rowErrors, clean } = validateRow(r);
      if (rowErrors.length) {
        errors.push({ line: r.line, reasons: rowErrors });
        continue;
      }
      if (seenInFile.has(clean.email)) {
        duplicatesInFile++;
        errors.push({
          line: r.line,
          reasons: [`e-mail repetido na planilha (primeira ocorrência na linha ${seenInFile.get(clean.email)})`],
        });
        continue;
      }
      seenInFile.set(clean.email, r.line);
      valid.push(clean);
    }

    // 3) Gravação transacional, isolada por tenant, respeitando o plano
    const imported = valid.length
      ? await persistCustomers(auth.tenantId, auth.userId, valid)
      : 0;
    const alreadyExisting = valid.length - imported; // ignorados por ON CONFLICT

    // 4) Resumo
    return res.status(200).json({
      summary: {
        totalRows: rows.length,
        imported,
        alreadyExisting,
        duplicatesInFile,
        invalid: errors.length - duplicatesInFile,
        failed: errors.length + alreadyExisting,
      },
      errors: errors.slice(0, MAX_ERRORS_IN_RESPONSE),
      errorsTruncated: errors.length > MAX_ERRORS_IN_RESPONSE,
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------- erros
// eslint-disable-next-line no-unused-vars
router.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    return res.status(status).json({ error: { code: err.code, message: err.message } });
  }
  if (err instanceof HttpError) {
    return res
      .status(err.status)
      .json({ error: { code: err.code, message: err.message, details: err.details } });
  }
  console.error('[customers/import]', err); // log interno; não vaza detalhes ao cliente
  return res
    .status(500)
    .json({ error: { code: 'INTERNAL_ERROR', message: 'Erro ao processar a importação.' } });
});

module.exports = router;