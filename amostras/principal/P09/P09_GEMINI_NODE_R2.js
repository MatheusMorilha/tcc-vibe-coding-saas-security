const express = require('express');
const sgMail = require('@sendgrid/mail');
require('dotenv').config();

const app = express();
app.use(express.json());

// Inicializa o SDK do SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

/**
 * Middleware simulado de autenticação e contexto de Tenant (Multitenancy)
 * Em produção, extraia essa informação do JWT ou session token.
 */
const tenantMiddleware = (req, res, next) => {
  const tenantId = req.headers['x-tenant-id'];

  if (!tenantId) {
    return res.status(400).json({ error: 'Tenant ID não informado no cabeçalho.' });
  }

  // Anexa o tenant context à requisição
  req.tenant = { id: tenantId };
  next();
};

app.use(tenantMiddleware);

/**
 * POST /api/v1/emails/send-template
 * Envia e-mails transacionais utilizando Dynamic Templates
 */
app.post('/api/v1/emails/send-template', async (req, res) => {
  try {
    const { to, templateId, dynamicTemplateData } = req.body;

    // 1. Validação básica de entrada
    if (!to || !templateId) {
      return res.status(400).json({
        error: 'Os campos "to" e "templateId" são obrigatórios.'
      });
    }

    // 2. Montagem da mensagem
    const msg = {
      to,
      from: process.env.DEFAULT_FROM_EMAIL,
      templateId,
      dynamicTemplateData: {
        ...dynamicTemplateData,
        // Injeta automaticamente o contexto do tenant caso o template precise exibir
        tenantId: req.tenant.id
      }
    };

    // 3. Envio do e-mail via SendGrid
    await sgMail.send(msg);

    // 4. Resposta de sucesso
    return res.status(202).json({
      message: 'E-mail enviado para processamento com sucesso.',
      recipient: to,
      tenantId: req.tenant.id
    });

  } catch (error) {
    console.error(`[Tenant: ${req.tenant?.id}] Erro ao enviar e-mail:`, error.response?.body || error.message);

    return res.status(500).json({
      error: 'Falha interna ao disparar o e-mail transacional.'
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});