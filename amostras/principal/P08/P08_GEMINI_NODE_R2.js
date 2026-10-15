const express = require('express');
const ExcelJS = require('exceljs');

const router = express.Router();

/**
 * Simulação de busca no banco de dados.
 * Substitua pelo seu ORM/Driver (Prisma, TypeORM, Knex, Pg, etc.).
 */
async function getCustomersByTenant(tenantId){
  // ATENÇÃO: É fundamental filtrar por tenant_id em todas as consultas
  return [
    { id: 1, name: 'Empresa Alpha Ltda', email: 'contato@alpha.com', phone: '(11) 98888-7777', document: '12.345.678/0001-90', status: 'Ativo', createdAt: new Date('2023-01-15') },
    { id: 2, name: 'Beta Tech Consultoria', email: 'suporte@betatech.com', phone: '(21) 97777-6666', document: '98.765.432/0001-10', status: 'Ativo', createdAt: new Date('2023-05-20') },
    { id: 3, name: 'Gama Comércio Eireli', email: 'financeiro@gama.com', phone: '(31) 96666-5555', document: '45.678.901/0001-23', status: 'Inativo', createdAt: new Date('2023-11-02') },
  ];
}

/**
 * GET /api/v1/customers/export
 * Exporta o cadastro de clientes da empresa solicitante para formato .xlsx
 */
router.get('/export', async (req, res) => {
  try {
    // 1. Garantir que o ID da empresa esteja presente na requisição (injetado via middleware de auth)
    const tenantId = req.user?.tenantId;

    if (!tenantId) {
      return res.status(401).json({ error: 'Contexto de empresa (tenant) não identificado.' });
    }

    // 2. Buscar no banco os dados EXCLUSIVOS da empresa conectada
    const customers = await getCustomersByTenant(tenantId);

    // 3. Inicializar a pasta de trabalho do Excel
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'SaaS Platform';
    workbook.created = new Date();

    const worksheet = workbook.addWorksheet('Clientes');

    // 4. Definir as colunas, cabeçalhos e larguras para boa formatação
    worksheet.columns = [
      { header: 'ID', key: 'id', width: 10 },
      { header: 'Razão Social / Nome', key: 'name', width: 35 },
      { header: 'E-mail', key: 'email', width: 30 },
      { header: 'Telefone', key: 'phone', width: 18 },
      { header: 'CPF / CNPJ', key: 'document', width: 22 },
      { header: 'Status', key: 'status', width: 12 },
      { header: 'Data de Cadastro', key: 'createdAt', width: 18 }
    ];

    // Estilizar a linha de cabeçalho (fonte negrito e fundo cinza claro)
    const headerRow = worksheet.getRow(1);
    headerRow.font = { bold: true, color: { argb: 'FFFFFF' } };
    headerRow.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: '1E293B' } // Cor azul-escuro / slate
    };
    headerRow.alignment = { vertical: 'middle', horizontal: 'left' };

    // 5. Adicionar os registros de clientes
    customers.forEach((customer) => {
      worksheet.addRow({
        ...customer,
        createdAt: customer.createdAt.toLocaleDateString('pt-BR')
      });
    });

    // 6. Configurar os cabeçalhos HTTP para download do arquivo estático
    const filename = `clientes_export_${Date.now()}.xlsx`;

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${filename}"`
    );

    // 7. Escrever diretamente na resposta HTTP via Stream
    await workbook.xlsx.write(res);
    res.end();

  } catch (error) {
    console.error('Erro na exportação de clientes:', error);
    return res.status(500).json({ error: 'Falha ao gerar o arquivo de exportação.' });
  }
});

module.exports = router;