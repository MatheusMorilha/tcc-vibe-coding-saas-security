const express = require('express');
const ExcelJS = require('exceljs');
const router = express.Router();

// Middleware simulado de autenticação/contexto multitenant
// Em produção, este middleware valida o JWT e injeta `req.user` com o `companyId`
function authenticateTenant(req, res, next){
  // Exemplo de payload autenticado
  req.user = {
    id: 'user_123',
    companyId: 'company_abc', // ID da empresa cliente (Tenant)
    role: 'ADMIN'
  };

  if (!req.user || !req.user.companyId) {
    return res.status(401).json({ error: 'Acesso não autorizado ou tenant inválido.' });
  }

  next();
}

// Simulação de repositório/banco de dados
async function getCustomersByCompany(companyId){
  // ATENÇÃO: É crítico incluir SEMPRE o filtro por companyId em qualquer consulta multitenant
  const mockDatabase = [
    { id: 'c1', companyId: 'company_abc', name: 'Tech Solutions Ltda', email: 'contato@tech.com', phone: '(11) 98888-7777', document: '12.345.678/0001-90', createdAt: new Date('2024-01-15') },
    { id: 'c2', companyId: 'company_abc', name: 'Mercado Central', email: 'financeiro@mercado.com', phone: '(11) 97777-6666', document: '98.765.432/0001-10', createdAt: new Date('2024-02-20') },
    { id: 'c3', companyId: 'company_xyz', name: 'Outra Empresa Tenant', email: 'outra@tenant.com', phone: '(21) 99999-0000', document: '11.111.111/0001-11', createdAt: new Date('2024-03-01') }
  ];

  return mockDatabase.filter(customer => customer.companyId === companyId);
}

/**
 * GET /api/v1/customers/export
 * Exporta a lista de clientes do tenant autenticado para um arquivo Excel (.xlsx)
 */
router.get('/export', authenticateTenant, async (req, res) => {
  try {
    const { companyId } = req.user;

    // 1. Busca os clientes garantindo o isolamento multitenant
    const customers = await getCustomersByCompany(companyId);

    // 2. Cria uma nova instância do Workbook
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'SaaS Platform';
    workbook.created = new Date();

    const worksheet = workbook.addWorksheet('Clientes');

    // 3. Define a estrutura das colunas
    worksheet.columns = [
      { header: 'ID', key: 'id', width: 15 },
      { header: 'Nome / Razão Social', key: 'name', width: 30 },
      { header: 'E-mail', key: 'email', width: 25 },
      { header: 'Telefone', key: 'phone', width: 18 },
      { header: 'CPF / CNPJ', key: 'document', width: 20 },
      { header: 'Data de Cadastro', key: 'createdAt', width: 18 }
    ];

    // Formatação do cabeçalho (negrito e fundo cinza claro)
    worksheet.getRow(1).font = { bold: true };
    worksheet.getRow(1).fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'F2F2F2' }
    };

    // 4. Popula os dados na planilha
    customers.forEach(customer => {
      worksheet.addRow({
        id: customer.id,
        name: customer.name,
        email: customer.email,
        phone: customer.phone,
        document: customer.document,
        createdAt: customer.createdAt.toLocaleDateString('pt-BR')
      });
    });

    // 5. Configura os cabeçalhos HTTP para download direto no navegador
    const fileName = `clientes_${companyId}_${Date.now()}.xlsx`;

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${fileName}"`
    );

    // 6. Escreve os dados no stream de resposta do Express
    await workbook.xlsx.write(res);
    res.end();

  } catch (error) {
    console.error('Erro ao exportar planilha de clientes:', error);
    res.status(500).json({ error: 'Erro interno ao gerar o arquivo de exportação.' });
  }
});

module.exports = router;