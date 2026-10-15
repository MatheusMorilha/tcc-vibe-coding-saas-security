const express = require('express');
const router = express.Router();

// Middleware simulado para extrair o contexto da requisição autenticada
// Em produção, isso deve vir do JWT/Sessão do usuário autenticado.
const extractTenantContext = (req, res, next) => {
  const tenantId = req.headers['x-tenant-id'];
  const userId = req.headers['x-user-id']; // Ou req.user.id via JWT

  if (!tenantId || !userId) {
    return res.status(401).json({ error: 'Contexto de autenticação/tenant inválido.' });
  }

  req.context = { tenantId, userId };
  next();
};

router.use(extractTenantContext);

/**
 * 1. SALVAR / ATUALIZAR RASCUNHO (UPSERT)
 * PUT /api/v1/drafts/:formType
 */
router.put('/drafts/:formType', async (req, res) => {
  try {
    const { tenantId, userId } = req.context;
    const { formType } = req.params;
    const draftData = req.body;

    if (!draftData || Object.keys(draftData).length === 0) {
      return res.status(400).json({ error: 'O corpo do rascunho não pode estar vazio.' });
    }

    // Exemplo usando uma query ORM/SQL genérica com suporte a Upsert
    // O isolamento POR TENANT é garantido no WHERE/ON CONFLICT
    /*
      Exemplo de Query SQL (PostgreSQL JSONB Upsert):
      INSERT INTO form_drafts (tenant_id, user_id, form_type, draft_data, updated_at)
      VALUES ($1, $2, $3, $4, NOW())
      ON CONFLICT (tenant_id, user_id, form_type)
      DO UPDATE SET
        draft_data = EXCLUDED.draft_data,
        updated_at = NOW()
      RETURNING *;
    */

    const savedDraft = await db.formDraft.upsert({
      where: {
        tenant_id_user_id_form_type: {
          tenant_id: tenantId,
          user_id: userId,
          form_type: formType,
        },
      },
      update: {
        draft_data: draftData,
        updated_at: new Date(),
      },
      create: {
        tenant_id: tenantId,
        user_id: userId,
        form_type: formType,
        draft_data: draftData,
      },
    });

    return res.status(200).json({
      message: 'Rascunho salvo com sucesso.',
      updatedAt: savedDraft.updated_at,
    });
  } catch (error) {
    console.error('Erro ao salvar rascunho:', error);
    return res.status(500).json({ error: 'Erro interno ao persistir o rascunho.' });
  }
});

/**
 * 2. RESTAURAR RASCUNHO
 * GET /api/v1/drafts/:formType
 */
router.get('/drafts/:formType', async (req, res) => {
  try {
    const { tenantId, userId } = req.context;
    const { formType } = req.params;

    // Busca o rascunho vinculando ESTRITAMENTE ao tenant e usuário atual
    const draft = await db.formDraft.findFirst({
      where: {
        tenant_id: tenantId,
        user_id: userId,
        form_type: formType,
      },
    });

    if (!draft) {
      return res.status(404).json({ message: 'Nenhum rascunho encontrado.' });
    }

    // Retorna o objeto reconstruído no campo `data`
    return res.status(200).json({
      formType: draft.form_type,
      data: draft.draft_data,
      updatedAt: draft.updated_at,
    });
  } catch (error) {
    console.error('Erro ao restaurar rascunho:', error);
    return res.status(500).json({ error: 'Erro interno ao buscar o rascunho.' });
  }
});

/**
 * 3. EXCLUIR RASCUNHO (Após submissão final do formulário)
 * DELETE /api/v1/drafts/:formType
 */
router.delete('/drafts/:formType', async (req, res) => {
  try {
    const { tenantId, userId } = req.context;
    const { formType } = req.params;

    await db.formDraft.deleteMany({
      where: {
        tenant_id: tenantId,
        user_id: userId,
        form_type: formType,
      },
    });

    return res.status(200).json({ message: 'Rascunho descartado com sucesso.' });
  } catch (error) {
    console.error('Erro ao deletar rascunho:', error);
    return res.status(500).json({ error: 'Erro interno ao remover rascunho.' });
  }
});

module.exports = router;