const express = require('express');
const sgMail = require('@sendgrid/mail');
const { z } = require('zod');
require('dotenv').config();

const app = express();
app.use(express.json());

// Configura a chave de API do SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

/**
 * Esquema de validação do payload recebido na API.
 * Garante que o ID do tenant, o destinatário e as variáveis necessárias estejam presentes.
 */
const sendEmailSchema = z.object({
  tenantId: z.string().min(1, 'O ID do tenant é obrigatório'),
  to: z.string().email('Endereço de e-mail do destinatário inválido'),
  templateId: z.string().min(1, 'O ID do template é obrigatório'),
  dynamicTemplateData: z.record(z.any(), {
    message: 'As variáveis do template devem ser um objeto key-value',
  }),
});

/**
 * POST /api/v1/emails/send
 * Rota para envio de e-mails transacionais parametrizados.
 */
app.post('/api/v1/emails/send', async (req, res) => {
  try {
    // 1. Validação do corpo da requisição
    const validationResult = sendEmailSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Dados de requisição inválidos',
        details: validationResult.error.flatten().fieldErrors,
      });
    }

    const { tenantId, to, templateId, dynamicTemplateData } = validationResult.data;

    // 2. Montagem da mensagem transacional
    const msg = {
      to,
      from: {
        email: process.env.EMAIL_FROM_ADDRESS,
        name: process.env.EMAIL_FROM_NAME || 'SaaS Platform',
      },
      templateId,
      dynamicTemplateData,
      // Metadata útil para rastreabilidade e métricas por tenant na plataforma
      customArgs: {
        tenant_id: tenantId,
      },
    };

    // 3. Disparo do e-mail via provedor
    await sgMail.send(msg);

    // TODO: Registrar log de envio no banco de dados vinculando ao tenantId

    return res.status(200).json({
      success: true,
      message: 'E-mail transacional enviado com sucesso',
      data: {
        recipient: to,
        tenantId,
      },
    });
  } catch (error) {
    console.error(`[Tenant Error] Falha ao enviar e-mail:`, error.response?.body || error.message);

    return res.status(500).json({
      error: 'Falha interna ao processar o envio do e-mail transacional',
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});