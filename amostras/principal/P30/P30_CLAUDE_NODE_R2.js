/**
 * POST /api/clientes/importar
 * Importação em lote de planilha (CSV ou XLSX) de clientes — SaaS multilocatário.
 *
 * Dependências: express, multer, csv-parse, exceljs, pg
 *
 * Pré-requisitos de banco (PostgreSQL):
 *
 *   CREATE TABLE clientes (
 *     id          BIGSERIAL PRIMARY KEY,
 *     tenant_id   BIGINT NOT NULL REFERENCES empresas(id),
 *     nome        VARCHAR(150) NOT NULL,
 *     email       VARCHAR(254),
 *     documento   VARCHAR(14)  NOT NULL,   -- CPF/CNPJ somente dígitos
 *     telefone    VARCHAR(20),
 *     criado_por  BIGINT,
 *     criado_em   TIMESTAMPTZ NOT NULL DEFAULT now(),
 *     UNIQUE (tenant_id, documento)        -- garante dedupe POR EMPRESA
 *   );
 *
 *   -- empresas: id, assinatura_status ('ativa' | ...), plano_limite_clientes (INT, NULL = ilimitado)
 */

'use strict';

const express = require('express');
const multer = require('multer');
const { parse } = require('csv-parse/sync');
const ExcelJS = require('exceljs');
const { Pool } = require('pg');

const pool = new Pool(); // configurado via variáveis PG* / DATABASE_URL
const router = express.Router();

// ----------------------------- Limites de segurança -----------------------------
const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB
const MAX_ROWS = 5000;                  // linhas por importação
const CHUNK_SIZE = 500;                 // linhas por INSERT
const MAX_ERRORS_IN_RESPONSE = 100;     // evita resposta gigante

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_BYTES, files: 1 },
});

// ----------------------------- Middlewares (assumidos) ---------------------------
// `authenticate` valida o JWT/sessão e popula req.user = { id, tenantId, role }.
// `rateLimit` deve limitar importações por empresa (ex.: 5/hora) para evitar abuso.
// Ambos são implementados em outra camada da aplicação.
const { authenticate, rateLimit } = require('../middlewares');

// ----------------------------- Utilidades de validação ---------------------------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const normalizarHeader = (h) =>
  String(h ?? '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_');

const ALIASES = {
  nome: 'nome',
  razao_social: 'nome',
  email: 'email',
  e_mail: 'email',
  documento: 'documento',
  cpf: 'documento',
  cnpj: 'documento',
  cpf_cnpj: 'documento',
  telefone: 'telefone',
  celular: 'telefone',
};

// Neutraliza CSV/Formula Injection caso o dado seja exportado depois para Excel.
const neutralizarFormula = (v) => (/^[=+\-@\t\r]/.test(v) ? `'${v}` : v);

const limpar = (v) => neutralizarFormula(String(v ?? '').replace(/[\u0000-\u001f]/g, ' ').trim());

function cpfValido(d) {
  if (!/^\d{11}$/.test(d) || /^(\d)\1+$/.test(d)) return false;
  for (const t of [9, 10]) {
    let soma = 0;
    for (let i = 0; i < t; i++) soma += Number(d[i]) * (t + 1 - i);
    const dv = ((soma * 10) % 11) % 10;
    if (dv !== Number(d[t])) return false;
  }
  return true;
}

function cnpjValido(d) {
  if (!/^\d{14}$/.test(d) || /^(\d)\1+$/.test(d)) return false;
  for (const t of [12, 13]) {
    const pesos = t === 12 ? [5,4,3,2,9,8,7,6,5,4,3,2] : [6,5,4,3,2,9,8,7,6,5,4,3,2];
    const soma = pesos.reduce((acc, p, i) => acc + p * Number(d[i]), 0);
    const dv = soma % 11 < 2 ? 0 : 11 - (soma % 11);
    if (dv !== Number(d[t])) return false;
  }
  return true;
}

/** Valida e normaliza uma linha. Retorna { ok, registro } ou { ok:false, motivo }. */
function validarLinha(bruta) {
  const nome = limpar(bruta.nome);
  const email = limpar(bruta.email).toLowerCase();
  const documento = String(bruta.documento ?? '').replace(/\D/g, '');
  const telefone = String(bruta.telefone ?? '').replace(/[^\d+]/g, '');

  if (!nome) return { ok: false, motivo: 'Nome é obrigatório' };
  if (nome.length > 150) return { ok: false, motivo: 'Nome excede 150 caracteres' };
  if (!documento) return { ok: false, motivo: 'Documento é obrigatório' };
  if (!cpfValido(documento) && !cnpjValido(documento)) {
    return { ok: false, motivo: 'CPF/CNPJ inválido' };
  }
  if (email && (email.length > 254 || !EMAIL_RE.test(email))) {
    return { ok: false, motivo: 'E-mail inválido' };
  }
  if (telefone.length > 20) return { ok: false, motivo: 'Telefone inválido' };

  return {
    ok: true,
    registro: { nome, email: email || null, documento, telefone: telefone || null },
  };
}

// ----------------------------- Leitura da planilha -------------------------------
/** Converte o arquivo em array de objetos { _linha, nome, email, documento, telefone }. */
async function lerPlanilha(file) {
  const nomeArq = (file.originalname || '').toLowerCase();
  const ehXlsx = nomeArq.endsWith('.xlsx') && file.buffer.slice(0, 2).toString() === 'PK';
  const ehCsv = nomeArq.endsWith('.csv');

  if (!ehXlsx && !ehCsv) {
    const e = new Error('Formato inválido. Envie um arquivo .csv ou .xlsx.');
    e.status = 400;
    throw e;
  }

  let matriz; // array de arrays: primeira linha = cabeçalho
  if (ehCsv) {
    matriz = parse(file.buffer, {
      bom: true,
      delimiter: [',', ';'], // Excel pt-BR exporta com ';'
      skip_empty_lines: true,
      relax_column_count: true,
      to_line: MAX_ROWS + 1,
    });
  } else {
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(file.buffer);
    const ws = wb.worksheets[0];
    if (!ws) return [];
    matriz = [];
    ws.eachRow({ includeEmpty: false }, (row) => {
      if (matriz.length > MAX_ROWS + 1) return;
      matriz.push(row.values.slice(1).map((c) => (c && c.text !== undefined ? c.text : c)));
    });
  }

  if (matriz.length < 2) return [];
  if (matriz.length - 1 > MAX_ROWS) {
    const e = new Error(`A planilha excede o limite de ${MAX_ROWS} linhas por importação.`);
    e.status = 413;
    throw e;
  }

  const cols = matriz[0].map((h) => ALIASES[normalizarHeader(h)] || null);
  if (!cols.includes('nome') || !cols.includes('documento')) {
    const e = new Error('Cabeçalho inválido: as colunas "nome" e "documento" são obrigatórias.');
    e.status = 400;
    throw e;
  }

  return matriz.slice(1).map((linha, i) => {
    const obj = { _linha: i + 2 }; // +2: cabeçalho + base 1
    cols.forEach((campo, idx) => {
      if (campo) obj[campo] = linha[idx];
    });
    return obj;
  });
}

// ----------------------------- Persistência em lote ------------------------------
/** INSERT multi-linha parametrizado; retorna quantas linhas foram realmente inseridas. */
async function inserirChunk(client, tenantId, userId, registros) {
  const params = [];
  const valores = registros.map((r, i) => {
    const b = i * 6;
    params.push(tenantId, r.nome, r.email, r.documento, r.telefone, userId);
    return `($${b + 1}, $${b + 2}, $${b + 3}, $${b + 4}, $${b + 5}, $${b + 6})`;
  });

  const { rowCount } = await client.query(
    `INSERT INTO clientes (tenant_id, nome, email, documento, telefone, criado_por)
     VALUES ${valores.join(',')}
     ON CONFLICT (tenant_id, documento) DO NOTHING`,
    params
  );
  return rowCount;
}

// ----------------------------- Rota ----------------------------------------------
router.post(
  '/clientes/importar',
  authenticate,
  rateLimit,
  upload.single('arquivo'),
  async (req, res) => {
    const inicio = Date.now();

    // O tenant vem SEMPRE do token autenticado — nunca do corpo/query/planilha.
    const { id: userId, tenantId, role } = req.user;

    if (!['admin', 'gerente'].includes(role)) {
      return res.status(403).json({ erro: 'Sem permissão para importar clientes.' });
    }
    if (!req.file) {
      return res.status(400).json({ erro: 'Envie o arquivo no campo "arquivo".' });
    }

    const client = await pool.connect();
    try {
      // 1) Lê e valida a planilha (fora da transação: não segura conexão/lock à toa)
      const linhas = await lerPlanilha(req.file);
      if (linhas.length === 0) {
        return res.status(400).json({ erro: 'A planilha não contém registros.' });
      }

      const erros = [];
      const validos = [];
      const vistos = new Map(); // documento -> linha (duplicidade dentro do arquivo)
      let duplicadosNoArquivo = 0;

      for (const l of linhas) {
        const r = validarLinha(l);
        if (!r.ok) {
          erros.push({ linha: l._linha, motivo: r.motivo });
          continue;
        }
        if (vistos.has(r.registro.documento)) {
          duplicadosNoArquivo++;
          erros.push({
            linha: l._linha,
            motivo: `Documento repetido (já informado na linha ${vistos.get(r.registro.documento)})`,
          });
          continue;
        }
        vistos.set(r.registro.documento, l._linha);
        validos.push(r.registro);
      }

      // 2) Transação: assinatura + cota + inserções de forma consistente
      await client.query('BEGIN');

      // Trava a linha da empresa: serializa importações concorrentes e evita estourar a cota
      const { rows } = await client.query(
        `SELECT assinatura_status, plano_limite_clientes
           FROM empresas WHERE id = $1 FOR UPDATE`,
        [tenantId]
      );
      const empresa = rows[0];

      if (!empresa || empresa.assinatura_status !== 'ativa') {
        await client.query('ROLLBACK');
        return res.status(402).json({ erro: 'Assinatura inativa. Regularize o plano para importar.' });
      }

      if (empresa.plano_limite_clientes !== null) {
        const { rows: cnt } = await client.query(
          'SELECT COUNT(*)::int AS total FROM clientes WHERE tenant_id = $1',
          [tenantId]
        );
        const disponiveis = empresa.plano_limite_clientes - cnt[0].total;
        // Pior caso: todos os válidos são novos. Se não couber, recusa tudo (comportamento previsível).
        if (validos.length > disponiveis) {
          await client.query('ROLLBACK');
          return res.status(403).json({
            erro: 'Limite de clientes do plano excedido.',
            limite_plano: empresa.plano_limite_clientes,
            vagas_disponiveis: Math.max(disponiveis, 0),
            registros_validos_na_planilha: validos.length,
          });
        }
      }

      let importados = 0;
      for (let i = 0; i < validos.length; i += CHUNK_SIZE) {
        importados += await inserirChunk(client, tenantId, userId, validos.slice(i, i + CHUNK_SIZE));
      }
      await client.query('COMMIT');

      // 3) Resumo
      const jaExistentes = validos.length - importados; // ON CONFLICT DO NOTHING
      return res.status(200).json({
        resumo: {
          total_linhas: linhas.length,
          importados,
          ja_existentes_ignorados: jaExistentes,
          duplicados_na_planilha: duplicadosNoArquivo,
          invalidos: erros.length - duplicadosNoArquivo,
          duracao_ms: Date.now() - inicio,
        },
        erros: erros.slice(0, MAX_ERRORS_IN_RESPONSE),
        erros_truncados: erros.length > MAX_ERRORS_IN_RESPONSE,
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      if (err.status) return res.status(err.status).json({ erro: err.message });

      // Detalhes internos só no log — nunca na resposta ao cliente
      console.error('[importar-clientes]', { tenantId, userId, err });
      return res.status(500).json({ erro: 'Falha ao processar a importação.' });
    } finally {
      client.release();
    }
  }
);

// Tratamento de erros do multer (arquivo grande demais etc.)
router.use((err, _req, res, next) => {
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    return res.status(status).json({ erro: `Upload inválido: ${err.message}` });
  }
  next(err);
});

module.exports = router;