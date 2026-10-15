// routes/customers.js
const express = require('express');
const XLSX = require('xlsx');
const {Customer }= require('../models');

const router = express.Router();

router.get('/companies/:companyId/customers/export', async (req, res)=> {
  try {
    const {companyId }= req.params;

    // A autorização deve garantir que o usuário autenticado
    // pertence à empresa informada.
    if (req.user.companyId!== companyId) {
      return res.status(403).json({
        error: 'Acesso não autorizado.'
      });
    }

    const customers = await Customer.findAll({
      where: { companyId },
      attributes: [
        'id',
        'name',
        'document',
        'email',
        'phone',
        'createdAt'
      ],
      order: [['name', 'ASC']],
      raw: true
    });

    const rows = customers.map(customer=> ({
      ID: customer.id,
      Nome: customer.name,
      Documento: customer.document,
      Email: customer.email,
      Telefone: customer.phone,
      'Data de cadastro': customer.createdAt
    }));

    const worksheet = XLSX.utils.json_to_sheet(rows);
    const workbook = XLSX.utils.book_new();

    XLSX.utils.book_append_sheet(workbook, worksheet, 'Clientes');

    const file = XLSX.write(workbook, {
      type: 'buffer',
      bookType: 'xlsx'
    });

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );

    res.setHeader(
      'Content-Disposition',
      'attachment; filename="clientes.xlsx"'
    );

    return res.send(file);
  }catch (error) {
    console.error('Erro ao exportar clientes:', error);

    return res.status(500).json({
      error: 'Não foi possível exportar os clientes.'
    });
  }
});

module.exports = router;