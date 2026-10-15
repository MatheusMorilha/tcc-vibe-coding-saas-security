const express = require('express');
const multer = require('multer');
const XLSX = require('xlsx');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// Exemplo de middleware de autenticação.
// Em produção, o tenantId deve vir de uma sessão/token validado,
// nunca de um campo enviado pelo cliente.
function autenticar(req, res, next) {
  req.usuario = {
    id: 'usuario-123',
    tenantId: 'empresa-456'
  };
  next();
}

// Exemplo de acesso ao banco.
// Substitua pela implementação real (PostgreSQL, MySQL etc.).
const db = {
  async transaction(callback) {
    const trx = {
      async query(sql, params) {
        // implementação real do banco
      }
    };

    return callback(trx);
  }
};

app.post(
  '/api/clientes/importar',
  autenticar,
  upload.single('planilha'),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        erro: 'Envie uma planilha no campo "planilha".'
      });
    }

    try {
      const workbook = XLSX.read(req.file.buffer, {
        type: 'buffer',
        cellDates: true
      });

      const primeiraAba = workbook.SheetNames[0];

      if (!primeiraAba) {
        return res.status(400).json({
          erro: 'A planilha não possui abas.'
        });
      }

      const registros = XLSX.utils.sheet_to_json(
        workbook.Sheets[primeiraAba],
        { defval: null }
      );

      const resumo = {
        total: registros.length,
        importados: 0,
        erros: 0,
        detalhesErros: []
      };

      await db.transaction(async (trx) => {
        for (let i = 0; i < registros.length; i++) {
          const registro = registros[i];
          const linha = i + 2; // considera a primeira linha como cabeçalho

          try {
            const nome = String(registro.nome || '').trim();
            const email = String(registro.email || '').trim().toLowerCase();

            if (!nome || !email) {
              throw new Error('Nome e e-mail são obrigatórios.');
            }

            // O tenantId vem do usuário autenticado.
            // Isso impede que a planilha escolha a empresa onde os
            // dados serão gravados.
            await trx.query(
              `
              INSERT INTO clientes
                (tenant_id, nome, email, telefone, criado_por)
              VALUES
                ($1, $2, $3, $4, $5)
              `,
              [
                req.usuario.tenantId,
                nome,
                email,
                registro.telefone,
                req.usuario.id
              ]
            );

            resumo.importados++;
          } catch (erro) {
            resumo.erros++;

            resumo.detalhesErros.push({
              linha,
              erro: erro.message
            });
          }
        }
      });

      return res.status(200).json({
        mensagem: 'Importação concluída.',
        resumo
      });
    } catch (erro) {
      console.error('Erro na importação:', erro);

      return res.status(500).json({
        erro: 'Não foi possível processar a planilha.'
      });
    }
  }
);

app.listen(3000, () => {
  console.log('API executando na porta 3000');
});
