import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { PrismaClient } from '@prisma/client';

const router = Router();
const prisma = new PrismaClient();

// 1. Configuração do Armazenamento do Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Organiza os arquivos por tenantId para isolamento no filesystem
    const tenantId = req.user?.tenantId;
    const uploadDir = path.join(__dirname, '..', '..', 'uploads', `tenant_${tenantId}`);

    // Cria o diretório se não existir
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Evita sobrescrita e colisão de nomes gerando um prefixo único
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, `attachment-${uniqueSuffix}${ext}`);
  },
});

// 2. Filtros de Segurança (MIME Types e Limite de Tamanho)
const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // Limite de 10 MB por arquivo
  },
  fileFilter: (req, file, cb) => {
    // Extensões e tipos permitidos para suporte
    const allowedMimeTypes = [
      'image/jpeg',
      'image/png',
      'image/webp',
      'application/pdf',
      'text/plain',
      'application/zip',
    ];

    if (allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Tipo de arquivo não permitido. Envie apenas imagens, PDF, TXT ou ZIP.'));
    }
  },
});

// Interface para estender o Request com o usuário autenticado do middleware JWT/Session
interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    tenantId: string;
  };
}

// 3. Rota de Upload do Anexo
router.post(
  '/tickets/:ticketId/attachments',
  upload.single('file'), // O nome do campo no formulário deve ser 'file'
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const { ticketId } = req.params;
    const file = req.file;

    // A. Validações básicas de autenticação e payload
    if (!req.user || !req.user.tenantId) {
      res.status(401).json({ error: 'Usuário não autenticado ou sem contexto de empresa.' });
      return;
    }

    if (!file) {
      res.status(400).json({ error: 'Nenhum arquivo foi enviado.' });
      return;
    }

    const tenantId = req.user.tenantId;
    const userId = req.user.id;

    try {
      // B. Isolamento Multitenant: Verifica se o chamado pertence AO MESMO TENANT do usuário
      const ticket = await prisma.ticket.findFirst({
        where: {
          id: ticketId,
          tenantId: tenantId, // GARANTIA MULTITENANT CRÍTICA
        },
      });

      if (!ticket) {
        // Remove o arquivo gravado caso a validação de acesso falhe
        fs.unlinkSync(file.path);
        res.status(404).json({ error: 'Chamado não encontrado ou você não possui permissão de acesso.' });
        return;
      }

      // C. Registro do Anexo na Base de Dados com isolamento multilocatário
      const attachment = await prisma.attachment.create({
        data: {
          filename: file.filename,
          originalName: file.originalname,
          mimeType: file.mimetype,
          size: file.size,
          path: file.path,
          ticketId: ticket.id,
          tenantId: tenantId, // Registra vínculo com a empresa cliente
          uploadedByUserId: userId,
        },
      });

      res.status(201).json({
        message: 'Arquivo anexado ao chamado com sucesso.',
        data: {
          id: attachment.id,
          originalName: attachment.originalName,
          size: attachment.size,
          createdAt: attachment.createdAt,
        },
      });
    } catch (error) {
      // Cleanup: remove arquivo do disco se houver falha de banco de dados
      if (file && fs.existsSync(file.path)) {
        fs.unlinkSync(file.path);
      }

      res.status(500).json({ error: 'Erro interno ao processar a gravação do anexo.' });
    }
  }
);

export default router;