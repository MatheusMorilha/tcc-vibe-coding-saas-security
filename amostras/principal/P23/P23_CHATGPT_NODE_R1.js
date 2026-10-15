// server.js
const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

/*
 * Em uma aplicação real, este middleware seria responsável por
 * autenticar o usuário e identificar a empresa (tenant) à qual
 * ele pertence.
 */
function authenticate(req, res, next) {
  // Exemplo apenas para demonstração.
  // Nunca confie em tenant_id enviado pelo cliente.
  req.user = {
    id: "user-123",
    tenantId: "company-456"
  };

  next();
}

app.use(authenticate);

/*
 * Modelo do objeto que existe na aplicação.
 *
 * O banco não precisa conhecer cada propriedade do formulário.
 * O objeto inteiro pode ser serializado em JSON.
 */
function createFormObject(data) {
  return {
    customer: {
      name: data.customer?.name || "",
      document: data.customer?.document || "",
      email: data.customer?.email || ""
    },

    address: {
      street: data.address?.street || "",
      number: data.address?.number || "",
      city: data.address?.city || "",
      state: data.address?.state || "",
      zipCode: data.address?.zipCode || ""
    },

    products: Array.isArray(data.products)
      ? data.products.map(product => ({
          id: product.id || null,
          description: product.description || "",
          quantity: Number(product.quantity || 0),
          price: Number(product.price || 0)
        }))
      : [],

    observations: data.observations || ""
  };
}

/*
 * POST /api/forms/drafts
 *
 * Cria um novo rascunho.
 */
app.post("/api/forms/drafts", async (req, res) => {
  const client = await pool.connect();

  try {
    const draftId = crypto.randomUUID();
    const formObject = createFormObject(req.body);

    await client.query(
      `
      INSERT INTO form_drafts (
        id,
        tenant_id,
        user_id,
        form_type,
        payload,
        created_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5::jsonb, NOW(), NOW())
      `,
      [
        draftId,
        req.user.tenantId,
        req.user.id,
        "customer_form",
        JSON.stringify(formObject)
      ]
    );

    res.status(201).json({
      id: draftId,
      data: formObject
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Não foi possível salvar o rascunho."
    });
  } finally {
    client.release();
  }
});

/*
 * PUT /api/forms/drafts/:id
 *
 * Atualiza um rascunho existente.
 */
app.put("/api/forms/drafts/:id", async (req, res) => {
  const client = await pool.connect();

  try {
    const formObject = createFormObject(req.body);

    const result = await client.query(
      `
      UPDATE form_drafts
         SET payload = $1::jsonb,
             updated_at = NOW()
       WHERE id = $2
         AND tenant_id = $3
         AND user_id = $4
      RETURNING id, payload, updated_at
      `,
      [
        JSON.stringify(formObject),
        req.params.id,
        req.user.tenantId,
        req.user.id
      ]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: "Rascunho não encontrado."
      });
    }

    res.json({
      id: result.rows[0].id,
      data: formObject,
      updatedAt: result.rows[0].updated_at
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Não foi possível atualizar o rascunho."
    });
  } finally {
    client.release();
  }
});

/*
 * GET /api/forms/drafts/:id
 *
 * Restaura o rascunho.
 */
app.get("/api/forms/drafts/:id", async (req, res) => {
  const client = await pool.connect();

  try {
    const result = await client.query(
      `
      SELECT
        id,
        form_type,
        payload,
        created_at,
        updated_at
      FROM form_drafts
      WHERE id = $1
        AND tenant_id = $2
        AND user_id = $3
      `,
      [
        req.params.id,
        req.user.tenantId,
        req.user.id
      ]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: "Rascunho não encontrado."
      });
    }

    const draft = result.rows[0];

    /*
     * payload é convertido novamente para o objeto utilizado
     * pela aplicação.
     */
    const formObject = createFormObject(draft.payload);

    res.json({
      id: draft.id,
      type: draft.form_type,
      data: formObject,
      createdAt: draft.created_at,
      updatedAt: draft.updated_at
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Não foi possível restaurar o rascunho."
    });
  } finally {
    client.release();
  }
});

/*
 * DELETE /api/forms/drafts/:id
 *
 * Remove o rascunho.
 */
app.delete("/api/forms/drafts/:id", async (req, res) => {
  const client = await pool.connect();

  try {
    const result = await client.query(
      `
      DELETE FROM form_drafts
      WHERE id = $1
        AND tenant_id = $2
        AND user_id = $3
      RETURNING id
      `,
      [
        req.params.id,
        req.user.tenantId,
        req.user.id
      ]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: "Rascunho não encontrado."
      });
    }

    res.status(204).send();
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Não foi possível remover o rascunho."
    });
  } finally {
    client.release();
  }
});

app.listen(3000, () => {
  console.log("API executando na porta 3000");
});
