const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const router = express.Router();

// 1. Configuração do Armazenamento (Multer)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Garante o isolamento de arquivos por empresa (tenantId) no sistema de arquivos
    const tenantId = req.user.tenantId;
    const uploadDir = path.join(__dirname, '..', 'uploads', `tenant_${tenantId}`);

    // Cria o diretório do locatário caso ainda não exista
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Gera um nome único de arquivo usando hash para evitar sobrescritas e path traversal
    const uniqueSuffix = crypto.randomBytes(16).toString('hex');
    const extension = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${uniqueSuffix}${extension}`);
  }
});

// 2. Filtro e Restrições do Arquivo
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // Limite máximo de 10 MB
  },
  fileFilter: (req, file, cb) => {
    // Tipos de arquivos permitidos
    const allowedMimeTypes = [
      'image/jpeg',
      'image/png',
      'image/webp',
      'application/pdf',
      'text/plain'
    ];

    if (allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Tipo de arquivo inválido. Permitidos apenas JPEG, PNG, WEBP, PDF e TXT.'));
    }
  }
});

// 3. Rota de Upload do Anexo
router.post('/tickets/:ticketId/attachments', upload.single('file'), async (req, res) => {
  try {
    const { ticketId } = req.params;
    const { tenantId, id: userId } = req.user; // Obtido via middleware de autenticação JWT/Session

    if (!req.file) {
      return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
    }

    // A. Validação de Pertencimento (Multi-tenancy Safeguard)
    // Busca o chamado garantindo que ele pertence ao tenant do usuário logado
    const ticket = await db.ticket.findFirst({
      where: {
        id: ticketId,
        tenantId: tenantId
      }
    });

    if (!ticket) {
      // Se o arquivo foi salvo pelo multer mas o chamado não pertence ao tenant, exclui o arquivo enviado
      fs.unlinkSync(req.file.path);
      return res.status(404).json({ error: 'Chamado de suporte não encontrado.' });
    }

    // B. Registro do Vínculo no Banco de Dados
    const attachmentRecord = await db.ticketAttachment.create({
      data: {
        ticketId: ticket.id,
        tenantId: tenantId,
        uploadedByUserId: userId,
        originalName: req.file.originalname,
        storedFileName: req.file.filename,
        filePath: req.file.path,
        mimeType: req.file.mimetype,
        fileSizeBytes: req.file.size
      }
    });

    return res.status(201).json({
      message: 'Arquivo anexado ao chamado com sucesso.',
      attachment: {
        id: attachmentRecord.id,
        filename: attachmentRecord.originalName,
        size: attachmentRecord.fileSizeBytes,
        createdAt: attachmentRecord.createdAt
      }
    });

  } catch (error) {
    // Limpeza de resíduos em caso de erro no processamento
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    console.error('Erro ao processar anexo do chamado:', error);
    return res.status(500).json({ error: 'Erro interno ao salvar o anexo.' });
  }
});

module.exports = router;