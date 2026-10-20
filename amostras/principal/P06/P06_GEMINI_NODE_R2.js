const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const router = express.Router();

// Configuração do armazenamento do Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const tenantId = req.tenantId; // Obtido via middleware de autenticação/tenant
    const uploadDir = path.join(__dirname, `../uploads/${tenantId}/support-tickets`);

    // Cria o diretório de forma síncrona caso não exista (isolamento por tenant)
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Evita conflito de nomes adicionando timestamp único mantendo a extensão original
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, `${uniqueSuffix}${ext}`);
  }
});

// Filtro opcional para tipos de arquivos permitidos
const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = ['image/jpeg', 'image/png', 'application/pdf', 'text/plain'];
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Tipo de arquivo não suportado.'), false);
  }
};

const upload = multer({ 
  storage, 
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // Limite de 5MB
});

/**
 * Rota para upload de anexo de chamado de suporte
 * POST /api/tickets/:ticketId/attachments
 */
router.post('/tickets/:ticketId/attachments', upload.single('file'), async (req, res) => {
  const { tenantId, user } = req;
  const { ticketId } = req.params;
  const file = req.file;

  if (!file) {
    return res.status(400).json({ error: 'Nenhum arquivo enviado ou arquivo inválido.' });
  }

  try {
    // 1. Validar se o chamado pertence ao tenant atual
    // const ticket = await TicketModel.findOne({ _id: ticketId, tenantId });
    // if (!ticket) {
    //   // Remove o arquivo salvo se o chamado não pertencer ao tenant
    //   fs.unlinkSync(file.path);
    //   return res.status(404).json({ error: 'Chamado não encontrado.' });
    // }

    // 2. Registrar o vínculo do arquivo no banco de dados (Exemplo com ORM/ODM)
    /*
    const attachment = await AttachmentModel.create({
      tenantId,
      ticketId,
      uploadedBy: user.id,
      originalName: file.originalname,
      storedName: file.filename,
      filePath: file.path,
      mimeType: file.mimetype,
      size: file.size,
      createdAt: new Date()
    });
    */

    // Simulação de registro bem-sucedido
    const attachmentRecord = {
      id: 'att_123456',
      ticketId,
      filename: file.filename,
      originalName: file.originalname,
      size: file.size,
      createdAt: new Date()
    };

    return res.status(201).json({
      message: 'Arquivo enviado e vinculado ao chamado com sucesso.',
      attachment: attachmentRecord
    });

  } catch (error) {
    // Em caso de erro no banco de dados, remove o arquivo do disco para evitar órfãos
    if (file && fs.existsSync(file.path)) {
      fs.unlinkSync(file.path);
    }
    
    console.error('Erro ao processar anexo:', error);
    return res.status(500).json({ error: 'Erro interno ao salvar o anexo.' });
  }
});

module.exports = router;