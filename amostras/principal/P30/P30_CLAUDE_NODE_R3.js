// routes/clientes.import.js
'use strict';

const express = require('express');
const multer = require('multer');
const ExcelJS = require('exceljs');
const { Readable } = require('stream');
const pool = require('../db');                       // instância de pg.Pool
const { autenticar, exigirPermissao } = require('../middlewares/auth');

const router = express.Router();

// ---------- Configurações ----------
const MAX_TAMANHO_ARQUIVO = 5 * 1024 * 1024; // 5 MB
const MAX_LINHAS = 5000;
const TAMANHO_LOTE = 500;
const MIMES_PERMITIDOS = new Set([
  'text/csv',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_TAMANHO_ARQUIVO, files: 1 },
  fileFilter: (_req, file, cb) => {
    const extOk = /\.(csv|xlsx)$/i.test(file.originalname);
    if (!extOk || !MIMES_PERMITIDOS.has(file.mimetype)) {
      return cb(new Error('FORMATO_INVALIDO'));
    }
    cb(null, true);
  },
});

// ---------- Utilidades ----------
const apenasDigitos = (v) => String(v ?? '').replace(/\D/g, '');

// Evita formula injection caso o dado seja reexportado para planilha depois
const neutralizarFormula = (v) =>
  typeof v === 'string' && /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;

const texto = (cel) => {
  if (cel == null) return '';
  // exceljs pode devolver objetos (hyperlink, richText, fórmula)
  if (typeof cel === 'object') {
    if (cel.text) return String(cel.text).trim();
    if (cel.richText) return cel.richText.map((p) => p.text).join('').trim();
    if (cel.result != null) return String(cel.result).trim();
    return '';
  }
  return String(cel).trim();
};

function cpfValido(cpf) {
  if (cpf.length !== 11 || /^(\d)\1+$/.test(cpf)) return false;
  const calc = (base, pesoInicial) => {
    let soma = 0;
    for (let i = 0; i < base.length; i++) soma += Number(base[i]) * (pesoInicial - i);
    const r = (soma * 10) % 11;
    return r === 10 ? 0 : r;
  };
  return calc(cpf.slice(0, 9), 10) === Number(cpf[9]) &&
         calc(cpf.slice(0, 10), 11) === Number(cpf[10]);
}

function cnpjValido(cnpj) {
  if (cnpj.length !== 14 || /^(\d)\1+$/.test(cnpj)) return false;
  const calc = (base) => {
    const pesos = base.length === 12
      ? [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
      : [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const soma = base.split('').reduce((acc, d, i) => acc + Number(d) * pesos[i], 0);
    const r = soma % 11;
    return r < 2 ? 0 : 11 - r;
  };
  return calc(cnpj.slice(0, 12)) === Number(cnpj[12]) &&
         calc(cnpj.slice(0, 13)) === Number(cnpj[13]);
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function validarLinha(bruto) {
  const nome = texto(bruto.nome);
  const documento = apenasDigitos(texto(bruto.documento));
  const email = texto(bruto.email).toLowerCase();
  const telefone = apenasDigitos(texto(bruto.telefone));

  if (!nome) return { erro: 'Nome é obrigatório' };
  if (nome.length > 200) return { erro: 'Nome excede 200 caracteres' };
  if (!documento) return { erro: 'Documento é obrigatório' };
  if (!(cpfValido(documento) || cnpjValido(documento))) {
    return { erro: 'CPF/CNPJ inválido' };
  }
  if (email && (email.length > 254 || !EMAIL_RE.test(email))) {
    return { erro: 'E-mail inválido' };
  }
  if (telefone && (telefone.length < 10 || telefone.length > 13)) {
    return { erro: 'Telefone inválido' };
  }

  return {
    registro: {
      nome: neutralizarFormula(nome),
      documento,
      email: email || null,
      telefone: telefone || null,
    },
  };
}

// Lê CSV ou XLSX e devolve array de objetos { nome, documento, email, telefone, _linha }
async function lerPlanilha(file) {
  const wb = new ExcelJS.Workbook();
  const ehCsv = /\.csv$/i.test(file.originalname);

  if (ehCsv) {
    await wb.csv.read(Readable.from(file.buffer), {
      parserOptions: { delimiter: [',', ';'] },
    });
  } else {
    await wb.xlsx.load(file.buffer);
  }

  const ws = wb.worksheets[0];
  if (!ws) throw new Error('PLANILHA_VAZIA');

  // Mapeia cabeçalhos (linha 1), tolerando maiúsculas e acentos
  const normaliza = (s) =>
    texto(s).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  const mapa = {};
  ws.getRow(1).eachCell((cel, col) => {
    const h = normaliza(cel.value);
    if (['nome', 'razao social'].includes(h)) mapa.nome = col;
    else if (['documento', 'cpf', 'cnpj', 'cpf/cnpj'].includes(h)) mapa.documento = col;
    else if (['email', 'e-mail'].includes(h)) mapa.email = col;
    else if (['telefone', 'celular', 'fone'].includes(h)) mapa.telefone = col;
    // qualquer outra coluna (inclusive empresa_id) é deliberadamente ignorada
  });

  if (!mapa.nome || !mapa.documento) throw new Error('CABECALHO_INVALIDO');
  if (ws.actualRowCount - 1 > MAX_LINHAS) throw new Error('LIMITE_LINHAS');

  const linhas = [];
  ws.eachRow({ includeEmpty: false }, (row, numero) => {
    if (numero === 1) return;
    linhas.push({
      _linha: numero,
      nome: row.getCell(mapa.nome).value,
      documento: row.getCell(mapa.documento).value,
      email: mapa.email ? row.getCell(mapa.email).value : null,
      telefone: mapa.telefone ? row.getCell(mapa.telefone).value : null,
    });
  });
  return linhas;
}

// INSERT multilinha parametrizado; retorna quantos foram realmente inseridos
async function inserirLote(client, empresaId, lote) {
  const valores = [];
  const placeholders = lote.map((r, i) => {
    const b = i * 5;
    valores.push(empresaId, r.nome, r.documento, r.email, r.telefone);
    return `($${b + 1}, $${b + 2}, $${b + 3}, $${b + 4}, $${b + 5})`;
  });

  const { rows } = await client.query(
    `INSERT INTO clientes (empresa_id, nome, documento, email, telefone)
     VALUES ${placeholders.join(', ')}
     ON CONFLICT (empresa_id, documento) DO NOTHING
     RETURNING documento`,
    valores
  );
  return new Set(rows.map((r) => r.documento));
}

// ---------- Rota ----------
router.post(
  '/clientes/importar',
  autenticar,
  exigirPermissao('clientes:importar'),
  (req, res, next) =>
    upload.single('arquivo')(req, res, (err) => {
      if (!err) return next();
      const msgs = {
        LIMIT_FILE_SIZE: [413, 'Arquivo excede 5 MB'],
        FORMATO_INVALIDO: [415, 'Envie um arquivo .csv ou .xlsx'],
      };
      const [status, mensagem] = msgs[err.code] || msgs[err.message] || [400, 'Falha no upload'];
      res.status(status).json({ erro: mensagem });
    }),
  async (req, res) => {
    // Tenant SEMPRE do token autenticado, nunca da requisição/planilha
    const empresaId = req.auth.empresaId;

    if (!req.file) return res.status(400).json({ erro: 'Arquivo não enviado' });

    let linhas;
    try {
      linhas = await lerPlanilha(req.file);
    } catch (e) {
      const msgs = {
        PLANILHA_VAZIA: 'Planilha vazia',
        CABECALHO_INVALIDO: 'Cabeçalho deve conter ao menos as colunas "nome" e "documento"',
        LIMITE_LINHAS: `Máximo de ${MAX_LINHAS} linhas por importação`,
      };
      return res.status(422).json({ erro: msgs[e.message] || 'Não foi possível ler a planilha' });
    }

    // 1) Validação linha a linha + deduplicação interna da própria planilha
    const erros = [];
    const validos = [];
    const vistos = new Set();

    for (const bruto of linhas) {
      const { registro, erro } = validarLinha(bruto);
      if (erro) {
        erros.push({ linha: bruto._linha, motivo: erro });
        continue;
      }
      if (vistos.has(registro.documento)) {
        erros.push({ linha: bruto._linha, motivo: 'Documento repetido na planilha' });
        continue;
      }
      vistos.add(registro.documento);
      validos.push({ ...registro, _linha: bruto._linha });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 2) Trava a empresa: serializa importações concorrentes e confere assinatura/plano
      const { rows: [empresa] } = await client.query(
        `SELECT e.status_assinatura, p.limite_clientes
           FROM empresas e
           JOIN planos p ON p.id = e.plano_id
          WHERE e.id = $1
          FOR UPDATE OF e`,
        [empresaId]
      );

      if (!empresa || empresa.status_assinatura !== 'ativa') {
        await client.query('ROLLBACK');
        return res.status(402).json({ erro: 'Assinatura inativa' });
      }

      // 3) Descobre quais documentos já existem para esta empresa (para o resumo)
      let existentes = new Set();
      if (validos.length) {
        const { rows } = await client.query(
          `SELECT documento FROM clientes
            WHERE empresa_id = $1 AND documento = ANY($2::text[])`,
          [empresaId, validos.map((v) => v.documento)]
        );
        existentes = new Set(rows.map((r) => r.documento));
      }

      const novos = [];
      let duplicados = 0;
      for (const v of validos) {
        if (existentes.has(v.documento)) {
          duplicados++;
          erros.push({ linha: v._linha, motivo: 'Cliente já cadastrado' });
        } else {
          novos.push(v);
        }
      }

      // 4) Respeita a cota do plano
      let rejeitadosPorLimite = 0;
      let aGravar = novos;
      if (empresa.limite_clientes != null) {
        const { rows: [{ total }] } = await client.query(
          'SELECT COUNT(*)::int AS total FROM clientes WHERE empresa_id = $1',
          [empresaId]
        );
        const disponivel = Math.max(0, empresa.limite_clientes - total);
        if (novos.length > disponivel) {
          aGravar = novos.slice(0, disponivel);
          for (const v of novos.slice(disponivel)) {
            erros.push({ linha: v._linha, motivo: 'Limite de clientes do plano atingido' });
          }
          rejeitadosPorLimite = novos.length - disponivel;
        }
      }

      // 5) Grava em lotes
      let importados = 0;
      for (let i = 0; i < aGravar.length; i += TAMANHO_LOTE) {
        const lote = aGravar.slice(i, i + TAMANHO_LOTE);
        const inseridos = await inserirLote(client, empresaId, lote);
        importados += inseridos.size;
        // Conflito de corrida (improvável com a trava, mas tratado)
        for (const r of lote) {
          if (!inseridos.has(r.documento)) {
            duplicados++;
            erros.push({ linha: r._linha, motivo: 'Cliente já cadastrado' });
          }
        }
      }

      await client.query('COMMIT');

      erros.sort((a, b) => a.linha - b.linha);
      const status = importados === 0 && linhas.length > 0 ? 422 : 200;

      return res.status(status).json({
        resumo: {
          totalLinhas: linhas.length,
          importados,
          duplicados,
          invalidos: erros.filter((e) => !/já cadastrado|Limite/.test(e.motivo)).length,
          rejeitadosPorLimiteDoPlano: rejeitadosPorLimite,
        },
        erros: erros.slice(0, 200),           // evita resposta gigante
        errosTruncados: erros.length > 200,
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      console.error('[importacao-clientes]', { empresaId, msg: err.message });
      return res.status(500).json({ erro: 'Falha ao processar a importação' });
    } finally {
      client.release();
    }
  }
);

module.exports = router;