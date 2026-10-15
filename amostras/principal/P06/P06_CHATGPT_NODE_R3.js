const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs/promises");
const crypto = require("crypto");

const router = express.Router();

const UPLOAD_DIR = path.resolve(__dirname, "uploads", "tickets");

const storage = multer.diskStorage({
  destination: async (req, file, cb)=> {
    const tenantId = req.user.tenantId;
    const tenantDir = path.join(UPLOAD_DIR, tenantId);

    await fs.mkdir(tenantDir, { recursive: true });
    cb(null, tenantDir);
  },

  filename: (req, file, cb)=> {
    const extension = path.extname(file.originalname);
    const filename = `${crypto.randomUUID()}${extension}`;

    cb(null, filename);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10 MB
  }
});

router.post(
  "/tickets/:ticketId/attachments",
  authenticateUser,
  upload.single("file"),
  async (req, res)=> {
    if (!req.file) {
      return res.status(400).json({
        error: "Arquivo não enviado."
      });
    }

    const {ticketId }= req.params;
    const {tenantId, userId }= req.user;

    try {
      // IMPORTANTE:
      // A consulta deve sempre filtrar pelo tenantId.
      const ticket = await db.ticket.findFirst({
        where: {
          id: ticketId,
          tenantId
        }
      });

      if (!ticket) {
        await fs.unlink(req.file.path).catch(()=> {});

        return res.status(404).json({
          error: "Chamado não encontrado."
        });
      }

      const attachment = await db.ticketAttachment.create({
        data: {
          ticketId: ticket.id,
          tenantId,
          uploadedByUserId: userId,

          originalName: req.file.originalname,
          storedName: req.file.filename,
          mimeType: req.file.mimetype,
          size: req.file.size,

          path: path.relative(
            UPLOAD_DIR,
            req.file.path
          )
        }
      });

      return res.status(201).json({
        id: attachment.id,
        filename: attachment.originalName,
        size: attachment.size,
        mimeType: attachment.mimeType
      });
    }catch (error) {
      // Evita deixar arquivo órfão caso o registro no banco falhe.
      await fs.unlink(req.file.path).catch(()=> {});

      console.error(error);

      return res.status(500).json({
        error: "Não foi possível registrar o anexo."
      });
    }
  }
);

module.exports = router;