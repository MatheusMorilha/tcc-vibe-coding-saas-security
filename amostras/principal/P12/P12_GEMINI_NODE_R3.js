// cryptoUtils.js
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY_HEX = process.env.ENCRYPTION_KEY;

if (!KEY_HEX || KEY_HEX.length !== 64) {
  throw new Error('ENCRYPTION_KEY deve ser configurada no .env com exatamente 64 caracteres hexadecimais (32 bytes).');
}

const SECRET_KEY = Buffer.from(KEY_HEX, 'hex');

/**
 * Criptografa um texto ou objeto.
 * Retorna uma string no formato "iv:authTag:encryptedData" (em hex/base64).
 */
function encrypt(data){
  const text = typeof data === 'object' ? JSON.stringify(data) : String(data);
  const iv = crypto.randomBytes(12); // Vector de Inicialização de 12 bytes recomendado para GCM

  const cipher = crypto.createCipheriv(ALGORITHM, SECRET_KEY, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');

  // Concatena IV, Tag de Autenticação e Conteúdo Criptografado
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Descriptografa os dados armazenados (útil para uso posterior na rotina de integração)
 */
function decrypt(ciphertext){
  const parts = ciphertext.split(':');
  if (parts.length !== 3) {
    throw new Error('Formato de dados criptografados inválido.');
  }

  const [ivHex, authTagHex, encryptedHex] = parts;
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, SECRET_KEY, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  try {
    return JSON.parse(decrypted);
  } catch {
    return decrypted;
  }
}

module.exports = { encrypt, decrypt };

// erpCredentialsController.js
const express = require('express');
const router = express.Router();
const { encrypt } = require('./cryptoUtils');

// Exemplo de abstração do repositório/banco de dados
// Substitua pela query do seu ORM (Prisma, TypeORM, Sequelize, Knex, etc.)
const db = {
  async saveOrUpdateCredentials({ tenantId, erpProvider, encryptedCredentials, status, updatedBy }) {
    // Exemplo em SQL conceitual:
    // INSERT INTO erp_integrations (tenant_id, erp_provider, credentials, status, updated_by, updated_at)
    // VALUES ($1, $2, $3, $4, $5, NOW())
    // ON CONFLICT (tenant_id, erp_provider) DO UPDATE ...
    return {
      id: "int_12345",
      tenantId,
      erpProvider,
      status,
      updatedAt: new Date()
    };
  }
};

/**
 * POST /api/v1/integrations/erp/credentials
 * Middleware de autenticação prévio deve ter preenchido req.user com { id, tenantId }
 */
router.post('/integrations/erp/credentials', async (req, res) => {
  try {
    const tenantId = req.user?.tenantId;
    const userId = req.user?.id;

    if (!tenantId) {
      return res.status(401).json({ error: 'Locatário (tenant) não identificado.' });
    }

    const { erpProvider, credentials } = req.body;

    // 1. Validação dos dados de entrada
    if (!erpProvider || typeof erpProvider !== 'string') {
      return res.status(400).json({ error: 'O provedor do ERP (erpProvider) é obrigatório.' });
    }

    if (!credentials || typeof credentials !== 'object' || Object.keys(credentials).length === 0) {
      return res.status(400).json({ error: 'As credenciais do ERP devem ser um objeto válido.' });
    }

    // 2. Criptografia do payload de credenciais em repouso
    const encryptedCredentials = encrypt(credentials);

    // 3. Persistência no banco de dados vinculando estritamente ao tenant_id
    const integrationRecord = await db.saveOrUpdateCredentials({
      tenantId,
      erpProvider: erpProvider.toLowerCase().trim(),
      encryptedCredentials,
      status: 'CONFIGURED',
      updatedBy: userId
    });

    // 4. Resposta sem expor nenhum dado sensível ou hash completo
    return res.status(200).json({
      message: 'Credenciais de integração do ERP armazenadas com sucesso.',
      data: {
        integrationId: integrationRecord.id,
        erpProvider: integrationRecord.erpProvider,
        status: integrationRecord.status,
        updatedAt: integrationRecord.updatedAt
      }
    });

  } catch (error) {
    console.error(`[ERP Integration Error] Tenant: ${req.user?.tenantId} - ${error.message}`);
    return res.status(500).json({ error: 'Falha interna ao armazenar credenciais do ERP.' });
  }
});

module.exports = router;