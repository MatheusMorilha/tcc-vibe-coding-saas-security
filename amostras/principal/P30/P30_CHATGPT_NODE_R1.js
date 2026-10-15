const express = require('express');
const multer = require('multer');
const XLSX = require('xlsx');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// Exemplo de autenticação/tenant já resolvido pelo middleware.
function autenticar(req, res, next) {
  // Em produção, obtenha o tenantId exclusivamente do usuário autenticado.
  req.tenantId = req.user.tenantId;
  next();
}

// Simulação da camada de persistência.
const db = {
  async clienteExiste(tenantId, email) {
    // SELECT id FROM clientes WHERE tenant_id = ? AND email = ?
    return false;
  },

  async inserirCliente(cliente) {
    // INSERT INTO clientes (...) VALUES (...)
  }
};

app.post(
  '/api/clientes/importar',
  autenticar,
  upload.single('planilha'),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        erro: 'A planilha é obrigatória.'
      });
    }

    const resumo = {
      total: 0,
      importados: 0,
      ignorados: 0,
      erros: []
    };

    try {
      const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
      const primeiraAba = workbook.Sheets[workbook.SheetNames[0]];

      const registros = XLSX.utils.sheet_to_json(primeiraAba, {
        defval: null
      });

      resumo.total = registros.length;

      for (let i = 0; i < registros.length; i++) {
        const linha = i + 2;

        try {
          const nome = String(registros[i].nome || '').trim();
          const email = String(registros[i].email || '').trim().toLowerCase();

          if (!nome || !email) {
            resumo.ignorados++;
            resumo.erros.push({
              linha,
              motivo: 'Nome e e-mail são obrigatórios.'
            });
            continue;
          }

          // O tenantId vem da autenticação, nunca da planilha.
          const existe = await db.clienteExiste(req.tenantId, email);

          if (existe) {
            resumo.ignorados++;
            resumo.erros.push({
              linha,
              email,
              motivo: 'Cliente já cadastrado.'
            });
            continue;
          }

          await db.inserirCliente({
            tenantId: req.tenantId,
            nome,
            email,
            telefone: registros[i].telefone || null
          });

          resumo.importados++;
        } catch (erro) {
          resumo.ignorados++;
          resumo.erros.push({
            linha,
            motivo: erro.message
          });
        }
      }

      return res.status(200).json({
        sucesso: true,
        resumo
      });
    } catch (erro) {
      return res.status(400).json({
        sucesso: false,
        erro: 'Não foi possível processar a planilha.',
        detalhe: erro.message
      });
    }
  }
);

app.listen(3000);
