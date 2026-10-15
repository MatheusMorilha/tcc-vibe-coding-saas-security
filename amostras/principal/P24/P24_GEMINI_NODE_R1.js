const express = require('express');
const multer = require('multer');
const { z } = require('zod');

const router = express.Router();

// 1. Configuração do Multer (armazenamento em memória)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 2 * 1024 * 1024, // Limite de 2 MB para segurança
  },
  fileFilter: (req, file, cb) => {
    // Aceita apenas arquivos .json ou MIME type application/json
    if (file.mimetype === 'application/json' || file.originalname.endsWith('.json')) {
      cb(null, true);
    } else {
      cb(new Error('Formato inválido. Apenas arquivos .json são permitidos.'));
    }
  },
});

// 2. Schema de validação dos parâmetros de configuração
const tenantConfigSchema = z.object({
  general: z.object({
    companyDisplayName: z.string().min(2).max(100).optional(),
    timezone: z.string().optional(),
    locale: z.enum(['pt-BR', 'en-US', 'es-ES']).optional(),
  }).optional(),
  features: z.object({
    enableTwoFactorAuth: z.boolean().optional(),
    enableAuditLogs: z.boolean().optional(),
    notifications: z.object({
      emailAlerts: z.boolean().optional(),
      slackIntegration: z.boolean().optional(),
      slackWebhookUrl: z.string().url().nullable().optional(),
    }).optional(),
  }).optional(),
  branding: z.object({
    primaryColor: z.string().regex(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/).optional(),
    logoUrl: z.string().url().optional(),
  }).optional(),
});

// Middlewares fictícios para demonstração de arquitetura real
const { requireAuth, requireTenantAdmin } = require('../middlewares/auth');
const { db } = require('../database'); // Instância da base de dados (Ex: Knex / Prisma / TypeORM)

/**
 * POST /api/v1/tenant/settings/upload-config
 * Upload e aplicação do arquivo de configuração do tenant.
 */
router.post(
  '/tenant/settings/upload-config',
  requireAuth,           // Valida JWT e injeta req.user
  requireTenantAdmin,    // Garante que o usuário tem role de administrador
  upload.single('configFile'), // Recebe o arquivo no campo 'configFile'
  async (req, res) => {
    try {
      // Isolamento Multitenant: O tenant_id VEM do usuário autenticado, nunca do payload do cliente
      const tenantId = req.user.tenant_id;

      if (!req.file) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message: 'Nenhum arquivo de configuração foi enviado.',
        });
      }

      // 3. Conversão do Buffer para JSON com tratamento de erro de parse
      let rawConfig;
      try {
        const fileContent = req.file.buffer.toString('utf-8');
        rawConfig = JSON.parse(fileContent);
      } catch (parseError) {
        return res.status(400).json({
          error: 'INVALID_JSON_FORMAT',
          message: 'O arquivo enviado não é um JSON válido.',
        });
      }

      // 4. Validação Estrutural e de Tipos usando Zod
      const validationResult = tenantConfigSchema.safeParse(rawConfig);
      if (!validationResult.success) {
        return res.status(422).json({
          error: 'VALIDATION_ERROR',
          message: 'O arquivo de configuração contém parâmetros inválidos.',
          details: validationResult.error.flatten().fieldErrors,
        });
      }

      const validatedSettings = validationResult.data;

      // 5. Execução em Transação de Banco de Dados
      await db.transaction(async (trx) => {
        // Busca as configurações atuais do tenant para realizar um merge superficial/profundo
        const currentTenant = await trx('tenants')
          .where({ id: tenantId })
          .select('settings', 'plan_tier')
          .first();

        if (!currentTenant) {
          throw new Error('TENANT_NOT_FOUND');
        }

        // Exemplo de verificação de regra de negócio (Plano Ativo / Feature Toggle)
        if (
          validatedSettings.features?.notifications?.slackIntegration &&
          currentTenant.plan_tier === 'BASIC'
        ) {
          const error = new Error('A integração com Slack não está disponível no plano contratado.');
          error.code = 'PLAN_LIMIT_EXCEEDED';
          throw error;
        }

        // Realiza o merge das configurações existentes com as novas enviadas
        const updatedSettings = {
          ...currentTenant.settings,
          ...validatedSettings,
          general: { ...currentTenant.settings?.general, ...validatedSettings.general },
          features: { ...currentTenant.settings?.features, ...validatedSettings.features },
          branding: { ...currentTenant.settings?.branding, ...validatedSettings.branding },
          updatedAt: new Date().toISOString(),
        };

        // Persiste as alterações garantindo o isolamento pelo tenant_id
        await trx('tenants')
          .where({ id: tenantId })
          .update({
            settings: JSON.stringify(updatedSettings),
            updated_at: new Date(),
          });

        // 6. Auditoria de Segurança
        await trx('audit_logs').insert({
          tenant_id: tenantId,
          user_id: req.user.id,
          action: 'TENANT_SETTINGS_FILE_UPLOAD',
          details: JSON.stringify({
            filename: req.file.originalname,
            sizeBytes: req.file.size,
            appliedSettingsKeys: Object.keys(validatedSettings),
          }),
          created_at: new Date(),
        });
      });

      return res.status(200).json({
        success: true,
        message: 'Configurações da empresa aplicadas com sucesso.',
      });

    } catch (error) {
      if (error.code === 'PLAN_LIMIT_EXCEEDED') {
        return res.status(403).json({
          error: error.code,
          message: error.message,
        });
      }

      console.error(`[Upload Config Error] Tenant: ${req.user?.tenant_id} - `, error);

      return res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Ocorreu um erro interno ao processar a configuração.',
      });
    }
  }
);

module.exports = router;