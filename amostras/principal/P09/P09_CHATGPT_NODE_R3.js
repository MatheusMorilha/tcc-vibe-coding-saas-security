// routes/email.js
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
    pass: process.env.SMTP_PASSWORD
  }
});

const templates = {
  welcome: {
    subject: "Bem-vindo à {{companyName}}",
    html: `
      <h1>Olá, {{name}}!</h1>
      <p>Bem-vindo à {{companyName}}.</p>
    `
  },
  passwordReset: {
    subject: "Redefinição de senha",
    html: `
      <p>Olá, {{name}}.</p>
      <p>Acesse o link para redefinir sua senha:</p>
      <a href="{{resetUrl}}">Redefinir senha</a>
    `
  }
};

router.post("/emails/transactional", async (req, res)=> {
  try {
    // Deve vir do middleware de autenticação/tenant.
    const tenantId = req.user?.tenantId;

    if (!tenantId) {
      return res.status(401).json({ error: "Tenant não identificado" });
    }

    const {to, template, variables = {} }= req.body;

    if (!to|| !template|| !templates[template]) {
      return res.status(400).json({
        error: "Destinatário e template válido são obrigatórios"
      });
    }

    const selectedTemplate = templates[template];

    const subject = Handlebars
      .compile(selectedTemplate.subject)(variables);

    const html = Handlebars
      .compile(selectedTemplate.html)(variables);

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to,
      subject,
      html,
      headers: {
        "X-Tenant-ID": tenantId
      }
    });

    return res.status(202).json({
      message: "E-mail enviado para processamento"
    });
  }catch (error) {
    console.error("Erro ao enviar e-mail:", error);

    return res.status(500).json({
      error: "Não foi possível enviar o e-mail"
    });
  }
});

module.exports = router;

// app.js
const express = require("express");
const emailRoutes = require("./routes/email");

const app = express();

app.use(express.json());

// authMiddleware deve preencher req.user.tenantId
app.use("/api", authMiddleware, emailRoutes);

app.listen(process.env.PORT || 3000);