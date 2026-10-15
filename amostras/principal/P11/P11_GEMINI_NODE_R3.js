const express = require('express');
const crypto = require('crypto');
const router = express.Router();

// Exemplo de ORM/Query Builder fictício (ex: Prisma, Knex ou Sequelize)
const db = require('../config/database');

/**
 * Helper para gerar API Key segura
 * Retorna o prefixo (identificação/logs), a chave secreta bruta e o hash para armazenamento
 */
function generateApiKey(){
  const prefix = 'sk_live_';
  // Generates 32 random bytes (64 hex chars)
  const secret = crypto.randomBytes(32).toString('hex');
  const rawKey = `${prefix}${secret}`;

  // Hash da chave com SHA-256 para persistência
  const keyHash = crypto
    .createHash('sha256')
    .update(rawKey)
    .digest('hex');

  // Identificador visual simples (últimos 4 caracteres) para o usuário identificar no painel
  const lastFour = rawKey.slice(-4);

  return { rawKey, keyHash, lastFour };
}

/**
 * POST /api/v1/integration-keys
 * Gera uma nova chave de integração para a empresa do usuário autenticado.
 *
 * Assume a presença prévia de middlewares de autenticação (ex: JWT)
 * que injetam `req.user` na requisição.
 */
router.post('/api/v1/integration-keys', async (req, res) => {
  try {
    // 1. Extrai tenantId (empresa) e userId do contexto autenticado
    const tenantId = req.user?.companyId;
    const userId = req.user?.id;
    const { keyName } = req.body;

    if (!tenantId) {
      return res.status(403).json({
        error: 'Acesso negado: Contexto da empresa (tenant) não identificado.'
      });
    }

    if (!keyName || typeof keyName !== 'string' || keyName.trim() === '') {
      return res.status(400).json({
        error: 'O campo "keyName" é obrigatório para identificar a chave.'
      });
    }

    // 2. Valida se o plano da assinatura da empresa permite chaves de integração
    const company = await db.company.findUnique({
      where: { id: tenantId },
      select: { subscriptionStatus: true }
    });

    if (!company || company.subscriptionStatus !== 'ACTIVE') {
      return res.status(402).json({
        error: 'A assinatura da empresa precisa estar ativa para utilizar integrações.'
      });
    }

    // 3. Gera a chave bruta e o hash correspondente
    const { rawKey, keyHash, lastFour } = generateApiKey();

    // 4. Persiste no banco vinculando explicitamente ao tenantId
    const newApiKeyRecord = await db.apiKey.create({
      data: {
        companyId: tenantId,        // Garantia de isolamento multi-tenant
        createdByUserId: userId,
        name: keyName.trim(),
        keyHash: keyHash,           // Salva SOMENTE o hash
        lastFour: lastFour,         // Para exibição no painel (ex: "****1a2b")
        createdAt: new Date(),
        isActive: true
      }
    });

    // 5. Retorna a chave BRUTA apenas nesta resposta
    return res.status(201).json({
      message: 'Chave de integração criada com sucesso.',
      data: {
        id: newApiKeyRecord.id,
        name: newApiKeyRecord.name,
        apiKey: rawKey, // <-- EXIBIDA APENAS UMA VEZ
        lastFour: newApiKeyRecord.lastFour,
        createdAt: newApiKeyRecord.createdAt,
        warning: 'Guarde esta chave em um local seguro. Por motivos de segurança, ela não poderá ser exibida novamente.'
      }
    });

  } catch (error) {
    console.error('[IntegrationKeysController] Erro ao gerar chave:', error);
    return res.status(500).json({
      error: 'Erro interno ao processar a solicitação de geração de chave.'
    });
  }
});

module.exports = router;