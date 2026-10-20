const express = require('express');
const crypto = require('crypto');
const router = express.Router();

/**
 * Middleware simulado de autenticação para extrair o contexto do tenant
 * Em produção, isso validaria o JWT e injetaria req.tenant no escopo da requisição.
 */
const authenticateTenantAdmin = (req, res, next) => {
  // Exemplo simulado obtido do token de autenticação
  req.tenant = {
    companyId: req.headers['x-company-id'] || '123e4567-e89b-12d3-a456-426614174000',
    userId: req.headers['x-user-id'] || 'user-uuid-admin',
    role: 'ADMIN'
  };
  next();
};

/**
 * Rota para gerar e persistir uma nova chave de integração
 * POST /api/integrations/keys
 */
router.post('/integrations/keys', authenticateTenantAdmin, async (req, res) => {
  const { companyId } = req.tenant;

  try {
    // 1. Gera uma chave de integração segura e aleatória
    const rawKey = `sk_live_${crypto.randomBytes(32).toString('hex')}`;

    // 2. Opcional (Boa prática): Gerar um hash da chave para armazenar no banco, 
    // permitindo comparar com segurança sem salvar a chave em texto plano.
    // Para simplificar o exemplo, armazenaremos a chave diretamente ou o hash.
    const keyHint = rawKey.slice(-4); // Mantém os últimos dígitos para identificação visual na UI

    // 3. Persistência no banco de dados compartilhado filtrando estritamente pelo companyId (Multi-tenancy)
    // Exemplo utilizando um ORM genérico:
    /*
    const newIntegrationKey = await db.integrationKey.create({
      data: {
        companyId,
        keyHash: crypto.createHash('sha256').update(rawKey).digest('hex'),
        keyHint,
        createdAt: new Date(),
        isActive: true
      }
    });
    */

    // Simulação do resultado da persistência
    const persistedKeyData = {
      id: 'key_uuid_123',
      companyId,
      keyHint,
      createdAt: new Date()
    };

    // 4. Retorna a chave em texto plano APENAS NESTE MOMENTO. 
    // Ela não poderá ser recuperada posteriormente por razões de segurança.
    return res.status(201).json({
      message: 'Chave de integração gerada com sucesso. Guarde-a em local seguro, pois ela não será exibida novamente.',
      integrationKey: rawKey,
      details: persistedKeyData
    });

  } catch (error) {
    console.error(`Erro ao gerar chave de integração para a empresa ${companyId}:`, error);
    return res.status(500).json({ error: 'Erro interno ao processar a solicitação.' });
  }
});

module.exports = router;