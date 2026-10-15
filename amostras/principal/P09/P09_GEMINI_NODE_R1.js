const express = require('express');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

// CONFIGURAÇÃO DO TRANSPORTE DE E-MAIL (SMTP)
// Em produção, utilize credenciais via variáveis de ambiente (process.env)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.mailtrap.io',
  port: parseInt(process.env.SMTP_PORT || '2525'),
  auth: {
    user: process.env.SMTP_USER || 'seu_usuario',
    pass: process.env.SMTP_PASS || 'sua_senha'
  }
});

// SIMULAÇÃO DE BANCO DE DADOS: Mapeamento de Templates Parametrizados
const emailTemplates = {
  welcome: {
    subject: (vars) => `Bem-vindo à plataforma, ${vars.userName}!`,
    html: (vars) => `
      <div style="font-family: sans-serif; color: #333;">
        <h2>Olá, ${vars.userName}!</h2>
        <p>Sua conta na empresa <strong>${vars.companyName}</strong> foi criada com sucesso.</p>
        <p>Acesse o seu painel através do link: <a href="${vars.loginUrl}">Acessar Conta</a></p>
        <br />
        <small>Este e-mail faz parte do plano ${vars.planName}.</small>
      </div>
    `
  },
  reset_password: {
    subject: () => 'Recuperação de Senha',
    html: (vars) => `
      <div style="font-family: sans-serif; color: #333;">
        <h2>Solicitação de Troca de Senha</h2>
        <p>Olá, ${vars.userName}. Clique no link abaixo para redefinir sua senha:</p>
        <a href="${vars.resetUrl}" style="background: #007bff; color: #fff; padding: 10px 15px; text-decoration: none; border-radius: 5px;">Redefinir Senha</a>
        <p>O link expira em ${vars.expiresIn}.</p>
      </div>
    `
  }
};

/**
 * ROTA: Envio de E-mail Transacional Parametrizado
 * POST /api/v1/emails/send-template
 */
app.post('/api/v1/emails/send-template', async (req, res) => {
  try {
    // Garantindo o contexto multilocatário (Tenant Isolation)
    const tenantId = req.headers['x-tenant-id'];
    if (!tenantId) {
      return res.status(400).json({ error: 'Header X-Tenant-ID é obrigatório.' });
    }

    const { recipient, templateId, templateVariables } = req.body;

    // Validação dos dados de entrada
    if (!recipient || !templateId || !templateVariables) {
      return res.status(400).json({
        error: 'Campos obrigatórios ausentes: recipient, templateId e templateVariables são necessários.'
      });
    }

    // Busca o template solicitado
    const template = emailTemplates[templateId];
    if (!template) {
      return res.status(404).json({ error: `Template '${templateId}' não encontrado.` });
    }

    // Compila assunto e corpo HTML com as variáveis recebidas
    const mailOptions = {
      from: '"SaaS Platform" <noreply@saasplatform.com>',
      to: recipient,
      subject: template.subject(templateVariables),
      html: template.html(templateVariables),
      // Tag de rastreamento para auditoria do tenant no provedor de e-mail
      headers: {
        'X-Tenant-ID': tenantId
      }
    };

    // Disparo do e-mail
    const info = await transporter.sendMail(mailOptions);

    return res.status(200).json({
      message: 'E-mail transacional enviado com sucesso.',
      messageId: info.messageId,
      tenantId
    });

  } catch (error) {
    console.error('Erro ao enviar e-mail transacional:', error);
    return res.status(500).json({ error: 'Falha interna ao processar envio do e-mail.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});