const express = require('express');
const { PrismaClient } = require('@prisma/client');

const router = express.Router();
const prisma = new PrismaClient();

/**
 * Middleware de contexto multilocatário (Exemplo simplificado)
 * Extrai o tenant_id e user_id do token JWT/sessão autenticada.
 */
function extractAuthContext(req, res, next){
  // Em produção, esses dados viriam do req.user (decodificado do JWT)
  const tenantId = req.headers['x-tenant-id'];
  const userId = req.headers['x-user-id'];

  if (!tenantId || !userId) {
    return res.status(401).json({ error: 'Contexto de autenticação ou tenant ausente.' });
  }

  req.auth = { tenantId, userId };
  next();
}

router.use(extractAuthContext);

/**
 * PUT /api/v1/drafts/:formSlug
 * Salva ou atualiza (upsert) o rascunho de um formulário.
 */
router.put('/drafts/:formSlug', async (req, res) => {
  try {
    const { formSlug } = req.params;
    const { tenantId, userId } = req.auth;
    const formData = req.body; // Payload JSON dinâmico do formulário

    if (!formData || typeof formData !== 'object' || Array.isArray(formData)) {
      return res.status(400).json({ error: 'O corpo da requisição deve ser um objeto JSON válido.' });
    }

    const draft = await prisma.formDraft.upsert({
      where: {
        tenantId_userId_formSlug: {
          tenantId,
          userId,
          formSlug,
        },
      },
      update: {
        data: formData,
      },
      create: {
        tenantId,
        userId,
        formSlug,
        data: formData,
      },
    });

    return res.status(200).json({
      message: 'Rascunho salvo com sucesso.',
      updatedAt: draft.updatedAt,
    });
  } catch (error) {
    console.error('Erro ao salvar rascunho:', error);
    return res.status(500).json({ error: 'Falha interna ao persistir o rascunho.' });
  }
});

/**
 * GET /api/v1/drafts/:formSlug
 * Restaura e retorna o objeto do formulário salvo.
 */
router.get('/drafts/:formSlug', async (req, res) => {
  try {
    const { formSlug } = req.params;
    const { tenantId, userId } = req.auth;

    const draft = await prisma.formDraft.findUnique({
      where: {
        tenantId_userId_formSlug: {
          tenantId,
          userId,
          formSlug,
        },
      },
    });

    if (!draft) {
      return res.status(404).json({ error: 'Nenhum rascunho encontrado para este formulário.' });
    }

    return res.status(200).json({
      formSlug: draft.formSlug,
      data: draft.data, // Objeto JSON pronto para reconstrução no frontend
      updatedAt: draft.updatedAt,
    });
  } catch (error) {
    console.error('Erro ao buscar rascunho:', error);
    return res.status(500).json({ error: 'Falha interna ao buscar o rascunho.' });
  }
});

/**
 * DELETE /api/v1/drafts/:formSlug
 * Descarta o rascunho após o envio definitivo do formulário.
 */
router.delete('/drafts/:formSlug', async (req, res) => {
  try {
    const { formSlug } = req.params;
    const { tenantId, userId } = req.auth;

    await prisma.formDraft.delete({
      where: {
        tenantId_userId_formSlug: {
          tenantId,
          userId,
          formSlug,
        },
      },
    });

    return res.status(204).send();
  } catch (error) {
    // P2025: Código do Prisma para registro não encontrado
    if (error.code === 'P2025') {
      return res.status(404).json({ error: 'Rascunho não encontrado para remoção.' });
    }
    console.error('Erro ao remover rascunho:', error);
    return res.status(500).json({ error: 'Falha interna ao excluir o rascunho.' });
  }
});

module.exports = router;