const express = require('express');
const multer = require('multer');
const XLSX = require('xlsx');
const {Pool }= require('pg');

const app = express();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10 MB
  }
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

/*
 * Exemplo de middleware de autenticação.
 * Em uma aplicação real, req.user deve ser preenchido
 * pelo mecanismo de autenticação/autorização.
 */
function authenticate(req, res, next) {
  // Exemplo:
  // req.user = {
  //   id: 123,
  //   tenantId: 456
  // };

  if (!req.user|| !req.user.tenantId) {
    return res.status(401).json({
      error: 'Usuário não autenticado.'
    });
  }

  next();
}

app.post(
  '/api/clientes/importar',
  authenticate,
  upload.single('arquivo'),
  async (req, res)=> {
    if (!req.file) {
      return res.status(400).json({
        error: 'Nenhum arquivo foi enviado.'
      });
    }

    const tenantId = req.user.tenantId;
    const client = await pool.connect();

    let processados= 0;
    let importados= 0;
    let ignorados= 0;
    const erros = [];

    try {
      /*
       * O tenant é obtido exclusivamente da sessão/token
       * do usuário autenticado.
       */
      const assinatura = await client.query(
        `
        SELECT id
        FROM assinaturas
        WHERE tenant_id = $1
          AND status = 'active'
        LIMIT 1
        `,
        [tenantId]
      );

      if (assinatura.rowCount=== 0) {
        return res.status(403).json({
          error: 'A empresa não possui uma assinatura ativa.'
        });
      }

      const workbook = XLSX.read(req.file.buffer, {
        type: 'buffer'
      });

      const primeiraAba = workbook.SheetNames[0];

      if (!primeiraAba) {
        return res.status(400).json({
          error: 'A planilha não possui nenhuma aba.'
        });
      }

      const worksheet = workbook.Sheets[primeiraAba];

      const registros = XLSX.utils.sheet_to_json(worksheet, {
        defval: null,
        raw: false
      });

      if (registros.length === 0) {
        return res.status(400).json({
          error: 'A planilha não possui registros.'
        });
      }

      await client.query('BEGIN');

      for (let i= 0; i< registros.length; i++) {
        const linha = registros[i];
        const numeroLinha = i+ 2;// linha 1 = cabeçalho

        processados++;

        try {
          const nome = String(linha.nome|| '').trim();
          const email = String(linha.email|| '').trim().toLowerCase();
          const documento = linha.documento
            ? String(linha.documento).trim()
            : null;
          const telefone = linha.telefone
            ? String(linha.telefone).trim()
            : null;

          // Validação dos dados obrigatórios.
          if (!nome) {
            throw new Error('Nome é obrigatório.');
          }

          if (!email) {
            throw new Error('E-mail é obrigatório.');
          }

          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            throw new Error('E-mail inválido.');
          }

          /*
           * O SAVEPOINT permite rejeitar somente o registro
           * problemático sem desfazer toda a importação.
           */
          await client.query(`SAVEPOINT linha_importacao`);

          /*
           * IMPORTANTE:
           * tenant_id vem do usuário autenticado.
           *
           * Portanto, mesmo que uma planilha tente informar
           * outro tenant_id, esse valor jamais será utilizado.
           */
          const resultado = await client.query(
            `
            INSERT INTO clientes (
              tenant_id,
              nome,
              email,
              documento,
              telefone,
              criado_em
            )
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (tenant_id, email)
            DO NOTHING
            RETURNING id
            `,
            [
              tenantId,
              nome,
              email,
              documento,
              telefone
            ]
          );

          await client.query(`RELEASE SAVEPOINT linha_importacao`);

          if (resultado.rowCount=== 0) {
            ignorados++;
            erros.push({
              linha: numeroLinha,
              email,
              erro: 'Cliente já cadastrado.'
            });
          }else {
            importados++;
          }
        }catch (erroLinha) {
          try {
            await client.query(
              `ROLLBACK TO SAVEPOINT linha_importacao`
            );
          }catch (_) {
            // O erro original da linha continua sendo reportado.
          }

          ignorados++;

          erros.push({
            linha: numeroLinha,
            erro: erroLinha.message
          });
        }
      }

      await client.query('COMMIT');

      return res.status(200).json({
        sucesso: true,
        resumo: {
          totalRegistros: registros.length,
          processados,
          importados,
          ignorados,
          erros: erros.length
        },
        erros
      });
    }catch (erro) {
      try {
        await client.query('ROLLBACK');
      }catch (_) {}

      console.error('Erro durante importação:', erro);

      return res.status(500).json({
        sucesso: false,
        error: 'Não foi possível concluir a importação.'
      });
    }finally {
      client.release();
    }
  }
);

app.listen(3000, ()=> {
  console.log('API executando na porta 3000');
});