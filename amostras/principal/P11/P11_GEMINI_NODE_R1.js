import express from 'express';
import crypto from 'node:crypto';
import { PrismaClient } from '@prisma/client';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * POST /api/v1/integration-keys
 * Gera uma nova chave de API para o tenant (empresa) do usuário autenticado.
 */
router.post('/integration-keys', async (req, res) => {
  try {
    // 1. Extrai o tenant (company) e usuário do contexto de autenticação (Middleware de Auth)
    const { companyId, userId, role } = req.user;
    const { name } = req.body;

    // Validação de Payload
    if (!name || typeof name !== 'string' || name.trim() === '') {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'O campo "name" é obrigatório para identificar a chave.'
      });
    }

    // 2. Validação de Autorização/RBAC (Apenas admins ou owners podem gerar chaves)
    if (!['ADMIN', 'OWNER'].includes(role)) {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: 'Você não tem permissão para gerenciar chaves de integração.'
      });
    }

    // 3. Validação de Regra de Negócio Multi-tenant (Verifica plano/assinatura ativa)
    const company = await prisma.company.findUnique({
      where: { id: companyId },
      select: { subscriptionStatus: true }
    });

    if (!company || company.subscriptionStatus !== 'ACTIVE') {
      return res.status(402).json({
        error: 'PAYMENT_REQUIRED',
        message: 'A empresa precisa estar com a assinatura ativa para gerar chaves de integração.'
      });
    }

    // 4. Geração da Chave Única em Texto Puro (Raw Key)
    // Ex: sk_live_8f3a1b... (64 caracteres hexadecimais aleatórios com prefixo)
    const rawBytes = crypto.randomBytes(32).toString('hex');
    const rawApiKey = `sk_live_${rawBytes}`;

    // 5. Hashing da Chave (SHA-256) para armazenamento seguro na base
    // A chave em texto puro NUNCA deve ser salva no banco de dados.
    const keyHash = crypto
      .createHash('sha256')
      .update(rawApiKey)
      .digest('hex');

    // Prefixo visível para identificação no painel (ex: sk_live_8f3a...)
    const keyPrefix = rawApiKey.substring(0, 15);

    // 6. Persistência na Base de Dados vinculada estritamente ao companyId
    const newApiKey = await prisma.apiKey.create({
      data: {
        companyId: companyId, // Vínculo explícito do tenant
        createdByUserId: userId,
        name: name.trim(),
        keyHash: keyHash,
        keyPrefix: keyPrefix,
        createdAt: new Date()
      }
    });

    // 7. Retorno ao solicitante (ÚNICA oportunidade em que a chave crua é exibida)
    return res.status(201).json({
      message: 'Chave de integração gerada com sucesso. Guarde-a em um local seguro!',
      data: {
        id: newApiKey.id,
        name: newApiKey.name,
        apiKey: rawApiKey, // Exibida apenas nesta resposta
        keyPrefix: newApiKey.keyPrefix,
        createdAt: newApiKey.createdAt
      }
    });

  } catch (error) {
    console.error('[POST /integration-keys] Erro ao gerar chave:', error);

    return res.status(500).json({
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Ocorreu um erro ao processar a geração da chave.'
    });
  }
});

export default router;