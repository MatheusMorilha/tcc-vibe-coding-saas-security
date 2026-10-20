const express = require("express");

const router = express.Router();

const MAX_DRAFT_BYTES = 1024 * 1024; // 1 MB

function isValidId(value) {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 128 &&
    /^[a-zA-Z0-9_-]+$/.test(value)
  );
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

// PUT /api/forms/:formId/draft
// Cria ou atualiza o rascunho do usuário autenticado.
router.put("/:formId/draft", async (req, res, next) => {
  try {
    const { formId } = req.params;
    const { data } = req.body;

    if (!isValidId(formId)) {
      return res.status(400).json({
        error: "Identificador de formulário inválido."
      });
    }

    if (!isPlainObject(data)) {
      return res.status(400).json({
        error: "O campo 'data' deve ser um objeto JSON."
      });
    }

    const serialized = JSON.stringify(data);

    if (Buffer.byteLength(serialized, "utf8") > MAX_DRAFT_BYTES) {
      return res.status(413).json({
        error: "O rascunho excede o limite de 1 MB."
      });
    }

    const now = new Date();

    const filter = {
      tenantId: req.user.tenantId,
      userId: req.user.id,
      formId
    };

    const result = await req.db.collection("form_drafts").updateOne(
      filter,
      {
        $set: {
          data,
          updatedAt: now
        },
        $setOnInsert: {
          createdAt: now
        }
      },
      { upsert: true }
    );

    return res.status(result.upsertedCount ? 201 : 200).json({
      message: "Rascunho salvo com sucesso.",
      formId,
      updatedAt: now.toISOString()
    });
  } catch (error) {
    next(error);
  }
});

// GET /api/forms/:formId/draft
// Recupera o rascunho e devolve os dados estruturados.
router.get("/:formId/draft", async (req, res, next) => {
  try {
    const { formId } = req.params;

    if (!isValidId(formId)) {
      return res.status(400).json({
        error: "Identificador de formulário inválido."
      });
    }

    const draft = await req.db.collection("form_drafts").findOne({
      tenantId: req.user.tenantId,
      userId: req.user.id,
      formId
    });

    if (!draft) {
      return res.status(404).json({
        error: "Rascunho não encontrado."
      });
    }

    // Reconstrói um objeto JavaScript independente a partir dos dados
    // persistidos, preservando a estrutura JSON do formulário.
    const restoredData = JSON.parse(JSON.stringify(draft.data));

    return res.status(200).json({
      formId: draft.formId,
      data: restoredData,
      createdAt: draft.createdAt,
      updatedAt: draft.updatedAt
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;