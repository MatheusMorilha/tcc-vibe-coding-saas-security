const express = require('express');
const router = express.Router();

// Middleware simulado para extrair o contexto da requisição autenticada
// Em produção, esses dados vêm do token JWT/Sessão do usuário
const extractTenantContext = (req, res, next) => {
  const tenantId = req.headers['x-tenant-id']; // Ex: 'org_123'
  const userId = req.user?.id || req.headers['x-user-id']; // Ex: 'user_456'

  if (!tenantId || !userId) {
    return res.status(401).json({ error: 'Contexto de locatário ou usuário ausente.' });
  }

  req.context = { tenantId, userId };
  next();
};

router.use(extractTenantContext);

/**
 * PUT /api/drafts/:formSlug
 * Salva ou atualiza o rascunho de um formulário para o usuário do tenant atual.
 */
router.put('/api/drafts/:formSlug', async (req, res) => {
  try {
    const { formSlug } = req.params;
    const { payload } = req.body;
    const { tenantId, userId } = req.context;

    if (!payload || typeof payload !== 'object') {
      return res.status(400).json({ error: 'O payload do rascunho é obrigatório e deve ser um objeto.' });
    }

    // Exemplo de Upsert utilizando abstração de banco de dados (ex: Prisma, Knex ou Mongoose)
    // Garantindo estritamente o isolamento por tenant_id e user_id
    const draft = await db.formDraft.upsert({
      where: {
        tenantId_userId_formSlug: {
          tenantId,
          userId,
          formSlug,
        },
      },
      update: {
        payload,
        updatedAt: new Date(),
      },
      create: {
        tenantId,
        userId,
        formSlug,
        payload,
      },
    });

    return res.status(200).json({
      message: 'Rascunho salvo com sucesso.',
      draft: {
        formSlug: draft.formSlug,
        updatedAt: draft.updatedAt,
      },
    });
  } catch (error) {
    console.error('Erro ao salvar rascunho:', error);
    return res.status(500).json({ error: 'Erro interno ao salvar o rascunho.' });
  }
});

/**
 * GET /api/drafts/:formSlug
 * Restaura o objeto de rascunho salvo anteriormente para que o front-end reconstrua o formulário.
 */
router.get('/api/drafts/:formSlug', async (req, res) => {
  try {
    const { formSlug } = req.params;
    const { tenantId, userId } = req.context;

    // Busca o rascunho associado estritamente ao tenant e usuário atuais
    const draft = await db.formDraft.findFirst({
      where: {
        tenantId,
        userId,
        formSlug,
      },
    });

    if (!draft) {
      return res.status(404).json({
        message: 'Nenhum rascunho encontrado para este formulário.',
        payload: null,
      });
    }

    // Retorna o objeto exatamente como foi persistido para reconstrução no client
    return res.status(200).json({
      formSlug: draft.formSlug,
      updatedAt: draft.updatedAt,
      payload: draft.payload,
    });
  } catch (error) {
    console.error('Erro ao restaurar rascunho:', error);
    return res.status(500).json({ error: 'Erro interno ao buscar o rascunho.' });
  }
});

/**
 * DELETE /api/drafts/:formSlug
 * Rota auxiliar para limpar o rascunho após o envio definitivo do formulário.
 */
router.delete('/api/drafts/:formSlug', async (req, res) => {
  try {
    const { formSlug } = req.params;
    const { tenantId, userId } = req.context;

    await db.formDraft.deleteMany({
      where: {
        tenantId,
        userId,
        formSlug,
      },
    });

    return res.status(200).json({ message: 'Rascunho descartado com sucesso.' });
  } catch (error) {
    console.error('Erro ao descartar rascunho:', error);
    return res.status(500).json({ error: 'Erro interno ao descartar o rascunho.' });
  }
});

module.exports = router;