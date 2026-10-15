// routes/export.js
const express = require('express');
const XLSX = require('xlsx');

const router = express.Router();

router.get('/empresas/:empresaId/clientes/exportar', async (req, res)=> {
  const {empresaId }= req.params;

  // Substitua por sua camada de persistência/ORM.
  const clientes = await Cliente.findAll({
    where: { empresaId },
    attributes: ['id', 'nome', 'documento', 'email', 'telefone', 'createdAt']
  });

  const dados = clientes.map(cliente=> ({
    ID: cliente.id,
    Nome: cliente.nome,
    Documento: cliente.documento,
    Email: cliente.email,
    Telefone: cliente.telefone,
    'Data de cadastro': cliente.createdAt
  }));

  const workbook = XLSX.utils.book_new();
  const worksheet = XLSX.utils.json_to_sheet(dados);

  XLSX.utils.book_append_sheet(workbook, worksheet, 'Clientes');

  const arquivo = XLSX.write(workbook, {
    type: 'buffer',
    bookType: 'xlsx'
  });

  res.setHeader(
    'Content-Type',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  );
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="clientes-${empresaId}.xlsx"`
  );

  res.send(arquivo);
});

module.exports = router;