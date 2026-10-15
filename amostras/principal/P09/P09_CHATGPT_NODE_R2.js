const express = require("express");
const nodemailer = require("nodemailer");
const Handlebars = require("handlebars");

const router = express.Router();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  },
});

/*
 * Exemplo de autenticação:
 * req.user = {
 *   id: "...",
 *   tenantId: "...",
 *   tenantPlan: "PRO"
 * }
 *
 * Em produção, essas informações devem vir
 * de um middleware autenticado.
 */
router.post("/transactional-email", async (req, res)=> {
  try {
    const {to, template, variables = {} }= req.body;

    if (!to|| !template) {
      return res.status(400).json({
        error: "Os campos 'to' e 'template' são obrigatórios.",
      });
    }

    if (!req.user?.tenantId) {
      return res.status(401).json({
        error: "Tenant não identificado.",
      });
    }

    // O tenant é obtido da sessão/token, nunca do body.
    const tenantId = req.user.tenantId;

    // Exemplo de regra de assinatura.
    const allowedPlans = ["PRO", "ENTERPRISE"];

    if (!allowedPlans.includes(req.user.tenantPlan)) {
      return res.status(403).json({
        error: "O plano atual não permite o envio de e-mails.",
      });
    }

    /*
     * Os templates devem ser carregados por tenant.
     * Exemplo de retorno:
     *
     * {
     *   subject: "Bem-vindo, {{name}}!",
     *   html: "<h1>Olá, {{name}}</h1>"
     * }
     *
     * Substitua esta função pela consulta ao seu banco.
     */
    const emailTemplate = await getTemplateForTenant(
      tenantId,
      template
    );

    if (!emailTemplate) {
      return res.status(404).json({
        error: "Template não encontrado.",
      });
    }

    const subject = Handlebars.compile(emailTemplate.subject)(
      variables
    );

    const html = Handlebars.compile(emailTemplate.html)(
      variables
    );

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to,
      subject,
      html,
    });

    return res.status(202).json({
      message: "E-mail transacional enviado.",
    });
  }catch (error) {
    console.error("Erro ao enviar e-mail:", error);

    return res.status(500).json({
      error: "Não foi possível enviar o e-mail.",
    });
  }
});

/*
 * Exemplo de acesso ao banco.
 *
 * É importante que tenantId faça parte do filtro.
 * Nunca busque um template apenas pelo seu ID/nome.
 */
async function getTemplateForTenant(tenantId, templateName) {
  // Exemplo:
  //
  // return db.emailTemplate.findFirst({
  //   where: {
  //     tenantId,
  //     name: templateName,
  //     active: true
  //   }
  // });

  return {
    subject: "Bem-vindo, {{name}}!",
    html: `
      <h1>Olá, {{name}}!</h1>
      <p>Sua empresa {{company}} está pronta para começar.</p>
    `,
  };
}

module.exports = router;

const express = require("express");
const emailRoutes = require("./routes/email");

const app = express();

app.use(express.json());

// Middleware de autenticação deve executar antes das rotas.
// app.use(authenticate);

app.use("/api", emailRoutes);

const port = process.env.PORT || 3000;

app.listen(port, ()=> {
  console.log(`API executando na porta${port}`);
});