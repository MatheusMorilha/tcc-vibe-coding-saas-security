const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');

const router = express.Router();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Configuração do armazenamento local com multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const tenantId = req.tenantId; // Obtido via middleware de autenticação/tenant
    const uploadDir = path.join(__dirname, `../uploads/tenant_${tenantId}`);

    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, `${uniqueSuffix}${ext}`);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 } // Limite de 5MB
});

/**
 * Rota para upload de anexo em um chamado de suporte com isolamento multilocatário (Shared Database, Shared Schema / Tenant ID)
 */
router.post('/support/tickets/:ticketId/attachments', upload.single('file'), async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { tenantId, userId } = req; // Injetados por middleware de autenticação JWT/SaaS
    const { ticketId } = req.params;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
    }

    await client.query('BEGIN');

    // 1. Validação de segurança: Garantir que o chamado pertence ao tenant autenticado
    const ticketCheck = await client.query(
      'SELECT id FROM support_tickets WHERE id = $1 AND tenant_id = $2',
      [ticketId, tenantId]
    );

    if (ticketCheck.rowCount === 0) {
      // Remove o arquivo salvo caso o ticket não pertença ao tenant
      fs.unlinkSync(file.path);
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Chamado não encontrado.' });
    }

    // 2. Registro do arquivo na base de dados mantendo o isolamento por tenant_id
    const insertQuery = `
      INSERT INTO ticket_attachments (
        tenant_id, 
        ticket_id, 
        file_name, 
        stored_file_name, 
        file_path, 
        file_size, 
        mime_type, 
        uploaded_by
      ) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id, file_name, created_at;
    `;

    const values = [
      tenantId,
      ticketId,
      file.originalname,
      file.filename,
      file.path,
      file.size,
      file.mimetype,
      userId
    ];

    const result = await client.query(insertQuery, values);

    await client.query('COMMIT');

    return res.status(201).json({
      message: 'Arquivo enviado e vinculado ao chamado com sucesso.',
      attachment: result.rows[0]
    });

  } catch (error) {
    await client.query('ROLLBACK');
    
    // Remove o arquivo em caso de falha no banco de dados
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    console.error('Erro ao processar anexo de suporte:', error);
    return res.status(500).json({ error: 'Erro interno ao processar o upload do arquivo.' });
  } finally {
    client.release();
  }
});

module.exports = router;