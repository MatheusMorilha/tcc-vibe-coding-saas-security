const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

const app = express();

const upload = multer({
  dest: path.join(__dirname, 'uploads'),
  limits: { fileSize: 10 * 1024 * 1024 }
});

// Autenticação deve popular req.user com tenantId.
app.post('/api/tickets/:ticketId/attachments', upload.single('file'), async (req, res)=> {
  if (!req.file) {
    return res.status(400).json({ error: 'Arquivo não enviado.' });
  }

  const {ticketId }= req.params;
  const tenantId = req.user.tenantId;

  try {
    // IMPORTANTE: sempre filtrar o chamado pelo tenantId.
    const ticket = await db.ticket.findFirst({
      where: { id: ticketId, tenantId }
    });

    if (!ticket) {
      return res.status(404).json({ error: 'Chamado não encontrado.' });
    }

    const attachment = await db.ticketAttachment.create({
      data: {
        id: crypto.randomUUID(),
        tenantId,
        ticketId: ticket.id,
        originalName: req.file.originalname,
        storedName: req.file.filename,
        path: req.file.path,
        mimeType: req.file.mimetype,
        size: req.file.size
      }
    });

    return res.status(201).json({
      id: attachment.id,
      name: attachment.originalName,
      size: attachment.size
    });
  }catch (error) {
    // Em produção, remover o arquivo se o registro não puder ser criado.
    return res.status(500).json({ error: 'Não foi possível registrar o anexo.' });
  }
});