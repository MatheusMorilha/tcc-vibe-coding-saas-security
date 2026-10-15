const express = require('express');
const multer = require('multer');
const { z } = require('zod');

const router = express.Router();

// Configuração do Multer para receber o arquivo em memória (sem gravar em disco)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 2 * 1024 * 1024, // Limite de 2MB
  },
  fileFilter: (req, file, cb) => {
    const allowedMimeTypes = ['application/json', 'text/plain'];
    if (allowedMimeTypes.includes(file.mimetype) || file.originalname.endsWith('.json')) {
      cb(null, true);
    } else {
      cb(new Error('Apenas arquivos JSON são permitidos.'));
    }
  },
});

// Schema de validação das configurações permitidas para o tenant
const configSchema = z.object({
  theme: z.enum(['light', 'dark', 'system']).default('light'),
  language: z.enum(['pt-BR', 'en-US', 'es-ES']).default('pt-BR'),
  timezone: z.string().default('America/Sao_Paulo'),
  notifications: z.object({
    emailAlerts: z.boolean().default(true),
    weeklyReport: z.boolean().default(false),
  }).default({}),
  maxUserSessions: z.number().int().min(1).max(50).optional(),
});

/**
 * Middleware de contexto multitenant (Exemplo)
 * Garante que a requisição está autenticada e extrai o tenantId do token JWT/sessão
 */
const requireTenantContext = (req, res, next) => {
  // O tenantId NUNCA deve vir do corpo da requisição ou de parâmetros não confiáveis.
  // Deve vir estritamente do token de autenticação validado.
  const tenantId = req.user?.tenantId;

  if (!tenantId) {
    return res.status(401).json({ error: 'Acesso negado. Tenant não identificado.' });
  }

  req.tenantId = tenantId;
  next();
};

/**
 * POST /api/tenant/config/upload
 * Processa o upload e aplicação de parâmetros do arquivo de configuração JSON
 */
router.post(
  '/api/tenant/config/upload',
  requireTenantContext,
  upload.single('file'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
      }

      // 1. Parse do conteúdo do arquivo JSON
      let rawConfig;
      try {
        const fileContent = req.file.buffer.toString('utf-8');
        rawConfig = JSON.parse(fileContent);
      } catch (parseError) {
        return res.status(400).json({
          error: 'Arquivo inválido. Certifique-se de que o arquivo é um JSON formatado corretamente.',
        });
      }

      // 2. Validação e sanitização dos parâmetros com Zod
      const validatedConfig = configSchema.parse(rawConfig);

      // 3. Persistência isolada no banco de dados
      // Exemplo fictício com ORM (Prisma/Sequelize/TypeORM):
      const updatedTenant = await db.tenant.update({
        where: { id: req.tenantId },
        data: {
          settings: validatedConfig,
          updatedAt: new Date(),
        },
      });

      return res.status(200).json({
        message: 'Configurações atualizadas com sucesso.',
        tenantId: req.tenantId,
        appliedSettings: validatedConfig,
      });

    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(422).json({
          error: 'Estrutura do arquivo de configuração inválida.',
          details: error.errors,
        });
      }

      console.error(`[TenantConfigUploadError] Tenant: ${req.tenantId}`, error);
      return res.status(500).json({ error: 'Erro interno ao processar arquivo de configuração.' });
    }
  }
);

module.exports = router;