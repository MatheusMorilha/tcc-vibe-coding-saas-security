// routes/clientes.js
const express = require('express');
const ExcelJS = require('exceljs');

const router = express.Router();

// Exemplo: o middleware de autenticação deve preencher req.tenantId.
router.get('/clientes/exportar', async (req, res)=> {
  try {
    const tenantId = req.tenantId;

    if (!tenantId) {
      return res.status(401).json({ error: 'Empresa não identificada.' });
    }

    // IMPORTANTE: filtrar sempre pelo tenant autenticado.
    const clientes = await req.db('clientes')
      .select([
        'id',
        'nome',
        'documento',
        'email',
        'telefone',
        'endereco',
        'cidade',
        'estado',
        'cep',
        'created_at'
      ])
      .where('tenant_id', tenantId)
      .orderBy('nome');

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Clientes');

    worksheet.columns= [
      { header: 'ID', key: 'id', width: 15 },
      { header: 'Nome', key: 'nome', width: 35 },
      { header: 'Documento', key: 'documento', width: 20 },
      { header: 'E-mail', key: 'email', width: 35 },
      { header: 'Telefone', key: 'telefone', width: 20 },
      { header: 'Endereço', key: 'endereco', width: 40 },
      { header: 'Cidade', key: 'cidade', width: 25 },
      { header: 'Estado', key: 'estado', width: 10 },
      { header: 'CEP', key: 'cep', width: 15 },
      { header: 'Cadastro', key: 'created_at', width: 20 }
    ];

    clientes.forEach(cliente=> {
      worksheet.addRow({
        ...cliente,
        created_at: cliente.created_at
          ? new Date(cliente.created_at).toLocaleString('pt-BR')
          : ''
      });
    });

    worksheet.getRow(1).font= { bold: true };
    worksheet.views= [{ state: 'frozen', ySplit: 1 }];

    const filename = `clientes-${tenantId}-${Date.now()}.xlsx`;

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${filename}"`
    );

    await workbook.xlsx.write(res);
    res.end();
  }catch (error) {
    console.error('Erro ao exportar clientes:', error);
    res.status(500).json({
      error: 'Não foi possível exportar os clientes.'
    });
  }
});

module.exports = router;