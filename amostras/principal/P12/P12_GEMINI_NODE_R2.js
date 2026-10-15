const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits para GCM

// A chave mestra deve ser uma string hex de 32 bytes (64 caracteres hex) configurada em variável de ambiente
const ENCRYPTION_KEY = Buffer.from(process.env.ERP_ENCRYPTION_KEY, 'hex');

/**
 * Criptografa uma string usando AES-256-GCM.
 * @param {string} text - O dado em texto puro (ex: JSON de credenciais).
 * @returns {string}String codificada contendo IV, Tag e Ciphertext em Base64.
 */
function encrypt(text){
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);

  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  const authTag = cipher.getAuthTag();

  // Retorna a combinação necessária para descriptografar posteriormente
  return JSON.stringify({
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    data: encrypted
  });
}

module.exports = { encrypt };

const express = require('express');
const router = express.Router();
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { encrypt } = require('../utils/crypto');

/**
 * POST /api/v1/integrations/erp
 * Armazena ou atualiza as credenciais do ERP para o locatário atual.
 */
router.post('/integrations/erp', async (req, res) => {
  try {
    // 1. Extração do contexto multilocatário (injetado pelo middleware de auth)
    const tenantId = req.tenantId;

    if (!tenantId) {
      return res.status(401).json({ error: 'Contexto do locatário não identificado.' });
    }

    // 2. Validação do payload recebido
    const { erpName, credentials } = req.body;

    if (!erpName || !credentials || typeof credentials !== 'object') {
      return res.status(400).json({
        error: 'É necessário fornecer o nome do ERP e um objeto válido com as credenciais.'
      });
    }

    // 3. Serialização e Criptografia dos dados sensíveis
    const credentialsJson = JSON.stringify(credentials);
    const encryptedCredentials = encrypt(credentialsJson);

    // 4. Persistência no banco de dados isolada por tenantId (Upsert)
    const integration = await prisma.erpIntegration.upsert({
      where: {
        tenantId: tenantId
      },
      update: {
        erpName: erpName,
        credentials: encryptedCredentials,
        updatedAt: new Date()
      },
      create: {
        tenantId: tenantId,
        erpName: erpName,
        credentials: encryptedCredentials
      }
    });

    // 5. Resposta sem expor as credenciais ou dados sensíveis
    return res.status(200).json({
      message: 'Credenciais do ERP armazenadas com sucesso.',
      data: {
        id: integration.id,
        erpName: integration.erpName,
        updatedAt: integration.updatedAt
      }
    });

  } catch (error) {
    console.error('[ERP Integration Error]:', error);
    return res.status(500).json({ error: 'Erro interno ao salvar credenciais do ERP.' });
  }
});

module.exports = router;