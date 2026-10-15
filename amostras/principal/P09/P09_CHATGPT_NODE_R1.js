// routes/email.js
const express = require("express");
const {Resend }= require("resend");

const router = express.Router();
const resend = new Resend(process.env.RESEND_API_KEY);

router.post("/transactional-email", async (req, res)=> {
  const {to, templateId, variables = {} }= req.body;

  if (!to|| !templateId) {
    return res.status(400).json({
      error: "to e templateId são obrigatórios",
    });
  }

  try {
    // Em produção, carregue o template pertencente ao tenant autenticado.
    const template = await getTemplateForTenant(req.tenant.id, templateId);

    if (!template) {
      return res.status(404).json({ error: "Template não encontrado" });
    }

    const html = renderTemplate(template.html, variables);

    const {data, error }= await resend.emails.send({
      from: process.env.EMAIL_FROM,
      to,
      subject: renderTemplate(template.subject, variables),
      html,
    });

    if (error) {
      return res.status(502).json({ error: "Falha ao enviar e-mail" });
    }

    return res.status(202).json({
      message: "E-mail aceito para envio",
      id: data.id,
    });
  }catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro interno" });
  }
});

function renderTemplate(template, variables) {
  return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, key)=>
    String(variables[key]?? "")
  );
}

// Implementação ilustrativa: deve consultar pelo tenant autenticado.
async function getTemplateForTenant(tenantId, templateId) {
  // SELECT ... WHERE id = templateId AND tenant_id = tenantId
  return {
    subject: "Olá, {{name}}",
    html: "<p>Olá, {{name}}!</p>",
  };
}

module.exports = router;