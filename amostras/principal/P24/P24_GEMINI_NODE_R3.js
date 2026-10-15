import express from 'express';
import multer from 'multer';
import yaml from 'js-yaml';
import { z } from 'zod';

const router = express.Router();

// 1. Configuração do Multer (Upload mantido em memória e limitado a 2MB)
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // Limitado a 2MB por arquivo
  fileFilter: (req, file, cb) => {
    const allowedMimeTypes = ['application/json', 'text/yaml', 'application/x-yaml'];
    const isYamlExtension = file.originalname.match(/\.(yaml|yml)$/i);
    const isJsonExtension = file.originalname.match(/\.json$/i);

    if (allowedMimeTypes.includes(file.mimetype) || isYamlExtension || isJsonExtension) {
      cb(null, true);
    } else {
      cb(new Error('Formato inválido. Apenas arquivos JSON ou YAML (.yml, .yaml) são aceitos.'));
    }
  }
});

// 2. Schema de Validação com Zod (Garante a estrutura esperada do arquivo)
const configSchema = z.object({
  theme: z.object({
    primaryColor: z.string().regex(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/, 'Cor primária deve ser um Hexadecimal válido'),
    darkMode: z.boolean().default(false)
  }).optional(),
  notifications: z.object({
    emailAlerts: z.boolean().default(true),
    webhookUrl: z.string().url('URL de webhook inválida').optional()
  }).optional(),
  features: z.object({
    enableBetaFeatures: z.boolean().default(false),
    maxUsersLimit: z.number().int().positive().optional()
  }).optional()
});

// 3. Rota da API
router.post('/settings/config-file', upload.single('configFile'), async (req, res) => {
  try {
    // A. Garantia de Tenant e Autenticação
    const tenantId = req.tenantContext?.id;
    if (!tenantId) {
      return res.status(401).json({ error: 'Contexto do locatário (tenant) não localizado.' });
    }

    // B. Verificação da presença do arquivo
    if (!req.file) {
      return res.status(400).json({ error: 'Nenhum arquivo enviado. Utilize o campo "configFile".' });
    }

    // C. Parsing do arquivo (JSON ou YAML)
    let parsedData;
    const fileContent = req.file.buffer.toString('utf-8');
    const filename = req.file.originalname.toLowerCase();

    try {
      if (filename.endsWith('.yaml') || filename.endsWith('.yml')) {
        parsedData = yaml.load(fileContent);
      } else {
        parsedData = JSON.parse(fileContent);
      }
    } catch (parseError) {
      return res.status(400).json({
        error: 'Erro de sintaxe no arquivo enviado.',
        details: parseError.message
      });
    }

    // D. Validação do Schema dos parâmetros
    const validationResult = configSchema.safeParse(parsedData);
    if (!validationResult.success) {
      return res.status(422).json({
        error: 'Estrutura de dados de configuração inválida.',
        details: validationResult.error.format()
      });
    }

    const validatedConfig = validationResult.data;

    // E. Persistência Isolada por Tenant (Exemplo com ORM fictício / SQL Seguro)
    // Garantimos explicitamente que a escrita é filtrada pelo `tenant_id`
    /*
    await db.tenantSettings.upsert({
      where: { tenantId: tenantId },
      update: {
        config: validatedConfig,
        updatedAt: new Date()
      },
      create: {
        tenantId: tenantId,
        config: validatedConfig
      }
    });
    */

    return res.status(200).json({
      message: 'Configurações do locatário atualizadas com sucesso.',
      tenantId: tenantId,
      appliedConfig: validatedConfig
    });

  } catch (error) {
    // Trata erros de limite do Multer ou falhas internas
    if (error instanceof multer.MulterError) {
      if (error.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: 'O arquivo excede o limite máximo permitido de 2MB.' });
      }
    }

    console.error(`[CONFIG_UPLOAD_ERROR] Tenant: ${req.tenantContext?.id}`, error);
    return res.status(500).json({ error: 'Erro interno ao processar a configuração do locatário.' });
  }
});

export default router;