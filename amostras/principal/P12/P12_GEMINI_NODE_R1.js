// services/cryptoService.js
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
// A chave deve ter exatos 32 bytes (256 bits), definida via variável de ambiente
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');

/**
 * Criptografa um texto ou objeto JSON
 * @param {string|object} data - Dados a serem criptografados
 * @returns {string}String codificada contendo IV, Auth Tag e o Ciphertext
 */
function encrypt(data){
  const textToEncrypt = typeof data === 'object' ? JSON.stringify(data) : String(data);

  // IV (Vetor de Inicialização) único de 12 bytes para cada operação
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);

  let encrypted = cipher.update(textToEncrypt, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Tag de autenticação necessária para garantir que os dados não foram adulterados
  const authTag = cipher.getAuthTag().toString('hex');

  // Formato de saída: iv:authTag:ciphertext
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Descriptografa uma credencial para uso posterior nas rotinas de integração
 * @param {string} encryptedString - String no formato iv:authTag:ciphertext
 * @returns {string|object}Conteúdo original descriptografado
 */
function decrypt(encryptedString){
  const [ivHex, authTagHex, encryptedHex] = encryptedString.split(':');

  if (!ivHex || !authTagHex || !encryptedHex) {
    throw new Error('Formato de credencial criptografada inválido.');
  }

  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);

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

// controllers/erpIntegrationController.js
const express = require('express');
const router = express.Router();
const { encrypt } = require('../services/cryptoService');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

/**
 * POST /api/v1/integrations/erp/credentials
 * Rota para salvar ou atualizar credenciais de acesso ao ERP da empresa cliente.
 */
router.post('/integrations/erp/credentials', async (req, res) => {
  try {
    // 1. Identificação do locatário (extraído do Middleware de Autenticação/JWT)
    const companyId = req.user?.companyId;

    if (!companyId) {
      return res.status(401).json({ error: 'Locatário não identificado ou token inválido.' });
    }

    // 2. Extração dos parâmetros da requisição
    const { erpProvider, apiUrl, apiKey, apiSecret, additionalConfig } = req.body;

    if (!erpProvider || !apiUrl || (!apiKey && !apiSecret)) {
      return res.status(400).json({
        error: 'Provedor ERP, URL da API e ao menos uma credencial (apiKey ou apiSecret) são obrigatórios.',
      });
    }

    // 3. Montagem e criptografia do payload de credenciais sensíveis
    const sensitiveData = {
      apiKey: apiKey || null,
      apiSecret: apiSecret || null,
      additionalConfig: additionalConfig || {},
    };

    const encryptedCredentials = encrypt(sensitiveData);

    // 4. Salva ou atualiza a integração no banco de dados (Isolamento por companyId)
    const integration = await prisma.erpIntegration.upsert({
      where: {
        companyId_erpProvider: {
          companyId: companyId,
          erpProvider: erpProvider,
        },
      },
      update: {
        apiUrl: apiUrl,
        credentials: encryptedCredentials,
        status: 'ACTIVE',
        updatedAt: new Date(),
      },
      create: {
        companyId: companyId,
        erpProvider: erpProvider,
        apiUrl: apiUrl,
        credentials: encryptedCredentials,
        status: 'ACTIVE',
      },
    });

    // 5. Retorno sanitizado (NUNCA expor as credenciais/chaves criptografadas na resposta)
    return res.status(200).json({
      message: 'Credenciais do ERP armazenadas com sucesso.',
      data: {
        id: integration.id,
        companyId: integration.companyId,
        erpProvider: integration.erpProvider,
        apiUrl: integration.apiUrl,
        status: integration.status,
        updatedAt: integration.updatedAt,
      },
    });
  } catch (error) {
    console.error('Erro ao salvar credenciais do ERP:', error);
    return res.status(500).json({ error: 'Erro interno ao processar a solicitação.' });
  }
});

module.exports = router;