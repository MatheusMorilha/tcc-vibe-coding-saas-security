const express = require('express');
const ExcelJS = require('exceljs');

const router = express.Router();

/**
 * Exemplo de middleware de autenticação/multatenancy.
 * Em uma aplicação real, ele valida o token JWT e extrai o tenant_id.
 */
function authenticateAndTenant(req, res, next){
  // Simulação de usuário autenticado extraído do token
  req.user = {
    id: 'usr_123',
    tenantId: 'tenant_company_abc' // Garantia do isolamento de dados
  };
  next();
}

/**
 * GET /api/v1/customers/export
 * Exporta a lista de clientes do tenant para um arquivo Excel (.xlsx)
 */
router.get('/export', authenticateAndTenant, async (req, res) => {
  try {
    const { tenantId } = req.user;

    // 1. Busca os dados no banco isolando estritamente pelo tenantId
    const customers = await fetchCustomersByTenant(tenantId);

    // 2. Cria uma nova planilha de trabalho
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'SaaS Platform';
    workbook.created = new Date();

    const worksheet = workbook.addWorksheet('Clientes');

    // 3. Define a estrutura das colunas
    worksheet.columns = [
      { header: 'ID', key: 'id', width: 15 },
      { header: 'Razão Social / Nome', key: 'name', width: 35 },
      { header: 'CNPJ / CPF', key: 'document', width: 20 },
      { header: 'E-mail', key: 'email', width: 30 },
      { header: 'Telefone', key: 'phone', width: 18 },
      { header: 'Status', key: 'status', width: 15 },
      { header: 'Data de Cadastro', key: 'createdAt', width: 20 }
    ];

    // 4. Estilização do cabeçalho
    const headerRow = worksheet.getRow(1);
    headerRow.font = { bold: true, color: { argb: 'FFFFFF' } };
    headerRow.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: '1F4E79' } // Azul escuro corporativo
    };
    headerRow.alignment = { vertical: 'middle', horizontal: 'center' };

    // 5. Adiciona os dados na planilha
    customers.forEach((customer) => {
      worksheet.addRow({
        id: customer.id,
        name: customer.name,
        document: customer.document,
        email: customer.email,
        phone: customer.phone,
        status: customer.status === 'ACTIVE' ? 'Ativo' : 'Inativo',
        createdAt: customer.createdAt.toISOString().split('T')[0]
      });
    });

    // 6. Configura os cabeçalhos de resposta HTTP para download do arquivo
    const fileName = `clientes_${tenantId}_${Date.now()}.xlsx`;

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${fileName}"`
    );

    // 7. Escreve os dados no stream de resposta HTTP
    await workbook.xlsx.write(res);
    res.end();

  } catch (error) {
    console.error('Erro ao exportar dados cadastrais:', error);
    res.status(500).json({ error: 'Falha interna ao gerar exportação.' });
  }
});

/**
 * Função utilitária para simulação de consulta ao banco de dados.
 * Substitua pelo ORM do projeto (Prisma, TypeORM, Sequelize, etc.).
 */
async function fetchCustomersByTenant(tenantId){
  // Exemplo de retorno tipado vindo da base compartilhada
  return [
    {
      id: 'cust_01',
      tenantId: tenantId,
      name: 'Empresa Exemplo LTDA',
      document: '12.345.678/0001-90',
      email: 'contato@exemplo.com.br',
      phone: '(11) 98888-7777',
      status: 'ACTIVE',
      createdAt: new Date('2024-01-15')
    },
    {
      id: 'cust_02',
      tenantId: tenantId,
      name: 'João da Silva',
      document: '123.456.789-00',
      email: 'joao@email.com',
      phone: '(45) 99999-0000',
      status: 'ACTIVE',
      createdAt: new Date('2024-02-20')
    }
  ];
}

module.exports = router;