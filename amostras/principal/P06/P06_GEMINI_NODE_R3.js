const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const router = express.Router();

// -----------------------------------------------------------------------------
// 1. Configuração do Armazenamento e Validações do Multer
// -----------------------------------------------------------------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Isolamento de diretório por empresa (tenant) para organização e segurança
    const companyId = req.user.company_id;
    const uploadDir = path.join(__dirname, '..', 'uploads', `company_${companyId}`);

    // Cria o diretório da empresa caso ainda não exista
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Sanitização do nome original para evitar problemas com caracteres especiais
    const sanitizedOriginalName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');

    // Sufixo único baseado no timestamp e número aleatório para evitar sobrescritas
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const ext = path.extname(sanitizedOriginalName);
    const baseName = path.basename(sanitizedOriginalName, ext);

    cb(null, `${baseName}-${uniqueSuffix}${ext}`);
  }
});

// Filtro de Segurança: Tipos de arquivos permitidos
const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = [
    'image/jpeg',
    'image/png',
    'application/pdf',
    'text/plain',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ];

  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Tipo de arquivo inválido. Apenas imagens, PDFs e documentos são permitidos.'), false);
  }
};

// Limite de tamanho por arquivo (ex: 10 MB)
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 10 * 1024 * 1024 } // 10 Megabytes
});

// -----------------------------------------------------------------------------
// 2. Rota de Upload do Anexo do Chamado
// -----------------------------------------------------------------------------
// Assumindo uso de middlewares prévios:
// - authenticateUser: Injeta req.user e req.company
// - checkActiveSubscription: Valida se o plano do cliente está ativo
router.post(
  '/tickets/:ticketId/attachments',
  // authenticateUser,
  // checkActiveSubscription,
  upload.single('file'),
  async (req, res) => {
    try {
      const { ticketId } = req.params;
      const { id: userId, company_id: companyId } = req.user;

      // Validação: Garante que o arquivo foi enviado na requisição
      if (!req.file) {
        return res.status(400).json({ error: 'Nenhum arquivo foi enviado.' });
      }

      // -----------------------------------------------------------------------
      // 3. Validação de Isolamento Multi-tenant (Isolamento de Dados)
      // -----------------------------------------------------------------------
      // Consulta hipotética ao banco de dados garantindo que o chamado pertence à MESMA empresa
      const ticket = await db('tickets')
        .where({ id: ticketId, company_id: companyId })
        .first();

      if (!ticket) {
        // Se o arquivo já foi gravado pelo Multer mas a validação falhou, removemos o arquivo gerado
        fs.unlinkSync(req.file.path);

        return res.status(404).json({
          error: 'Chamado não encontrado ou você não tem permissão para acessá-lo.'
        });
      }

      // -----------------------------------------------------------------------
      // 4. Registro do Vínculo do Arquivo no Banco de Dados
      // -----------------------------------------------------------------------
      const [attachmentRecord] = await db('ticket_attachments')
        .insert({
          ticket_id: ticket.id,
          company_id: companyId, // Vínculo explícito de tenant no registro do anexo
          uploaded_by_user_id: userId,
          original_name: req.file.originalname,
          file_name: req.file.filename,
          file_path: req.file.path,
          file_size: req.file.size,
          mime_type: req.file.mimetype,
          created_at: new Date()
        })
        .returning(['id', 'original_name', 'file_size', 'created_at']);

      return res.status(201).json({
        message: 'Anexo adicionado com sucesso.',
        attachment: attachmentRecord
      });

    } catch (error) {
      // Caso ocorra erro de execução e o arquivo tenha sido gravado, remove do disco
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }

      console.error('Erro ao anexar arquivo ao chamado:', error);
      return res.status(500).json({ error: 'Erro interno ao processar o upload do anexo.' });
    }
  }
);

// Middleware para captura de erros lançados pelo Multer (ex: arquivo maior que o limite)
router.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'O arquivo excede o limite máximo permitido de 10 MB.' });
    }
    return res.status(400).json({ error: err.message });
  } else if (err) {
    return res.status(400).json({ error: err.message });
  }
  next();
});

module.exports = router;