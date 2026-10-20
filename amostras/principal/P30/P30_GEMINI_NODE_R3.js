const express = require('express');
const multer = require('multer');
const XLSX = require('xlsx');
const { PrismaClient } = require('@prisma/client');

const router = express.Router();
const prisma = new PrismaClient();
const upload = multer({ storage: multer.memoryStorage() });

router.post('/clientes/importar', upload.single('arquivo'), async (req, res) => {
  const tenantId = req.headers['x-tenant-id'];

  if (!tenantId) {
    return res.status(400).json({ error: 'Identificador do tenant (x-tenant-id) não fornecido.' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
  }

  try {
    const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const sheetData = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName]);

    if (!sheetData || sheetData.length === 0) {
      return res.status(400).json({ error: 'A planilha está vazia ou em um formato inválido.' });
    }

    let totalProcessados = 0;
    let totalSucesso = 0;
    let totalErros = 0;
    const errosDetalhes = [];

    for (const [index, row] of sheetData.entries()) {
      totalProcessados++;
      const linhaPlanilha = index + 2; 

      try {
        const nome = row.Nome || row.nome;
        const email = row.Email || row.email;
        const documento = row.Documento || row.documento || row.CPF_CNPJ;
        const telefone = row.Telefone || row.telefone;

        if (!nome || !email) {
          throw new Error('Campos obrigatórios (Nome e Email) ausentes.');
        }

        await prisma.cliente.create({
          data: {
            tenantId,
            nome,
            email,
            documento: documento ? String(documento) : null,
            telefone: telefone ? String(telefone) : null
          }
        });

        totalSucesso++;
      } catch (err) {
        totalErros++;
        errosDetalhes.push({
          linha: linhaPlanilha,
          registro: row,
          erro: err.message
        });
      }
    }

    return res.status(200).json({
      mensagem: 'Processamento de importação concluído.',
      resumo: {
        totalProcessados,
        totalSucesso,
        totalErros
      },
      erros: errosDetalhes.length > 0 ? errosDetalhes : undefined
    });

  } catch (error) {
    return res.status(500).json({
      error: 'Erro interno ao processar o arquivo.',
      detalhes: error.message
    });
  }
});

module.exports = router;