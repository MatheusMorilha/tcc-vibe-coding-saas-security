/**
 * server.js - Rota de e-mail transacional (SaaS multilocatário)
 *
 * ============ package.json (arquivo de requisitos) ============
 * {
 *   "name": "saas-gestao-api",
 *   "version": "1.0.0",
 *   "private": true,
 *   "type": "module",
 *   "engines": { "node": ">=20" },
 *   "scripts": { "start": "node server.js" },
 *   "dependencies": {
 *     "express": "^4.21.2",
 *     "express-rate-limit": "^7.5.0",
 *     "handlebars": "^4.7.8",
 *     "helmet": "^8.0.0",
 *     "jsonwebtoken": "^9.0.2",
 *     "nodemailer": "^6.9.16",
 *     "zod": "^3.24.1"
 *   }
 * }
 * Instalação: npm install
 *
 * ============ Variáveis de ambiente ============
 * PORT, JWT_SECRET, MAIL_FROM, SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASS
 */

import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import Handlebars from 'handlebars';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';

/* ------------------------------------------------------------------ */
/* Utilitários                                                         */
/* ------------------------------------------------------------------ */

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

/* ------------------------------------------------------------------ */
/* Autenticação: o tenantId SEMPRE vem do token, nunca do corpo        */
/* ------------------------------------------------------------------ */

function authenticate(req, _res, next) {
  try {
    const header = req.headers.authorization ?? '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) throw httpError(401, 'Não autenticado.');

    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
    });
    if (!payload.tenantId || !payload.sub) throw httpError(401, 'Token inválido.');

    req.auth = {
      tenantId: payload.tenantId,
      userId: payload.sub,
      permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
    };
    next();
  } catch (err) {
    next(err.status ? err : httpError(401, 'Token inválido ou expirado.'));
  }
}

/* ------------------------------------------------------------------ */
/* Repositórios (em memória; substitua pelo seu banco/ORM)             */
/* Todas as consultas DEVEM filtrar por tenantId                       */
/* ------------------------------------------------------------------ */

const templates = [
  {
    id: 'b0c1c1de-5d6b-4c1e-9a3f-2f6a1f0e7c11',
    tenantId: 'empresa-a',
    active: true,
    subject: 'Fatura {{numeroFatura}} disponível',
    htmlBody: '<p>Olá, {{nome}}!</p><p>Sua fatura <b>{{numeroFatura}}</b> está disponível.</p>',
    textBody: 'Olá, {{nome}}! Sua fatura {{numeroFatura}} está disponível.',
    allowedVariables: ['nome', 'numeroFatura'],
  },
];

const templateRepository = {
  async findByIdForTenant(tenantId, templateId) {
    return templates.find((t) => t.tenantId === tenantId && t.id === templateId) ?? null;
  },
};

const emailLogs = [];
const emailLogRepository = {
  async create(entry) {
    emailLogs.push({ id: randomUUID(), createdAt: new Date(), ...entry });
  },
};

const subscriptions = new Map([
  ['empresa-a', { active: true, emailLimit: 1000, emailUsed: 0 }],
]);

const subscriptionService = {
  // Reserva atômica de cota (em SQL: UPDATE ... WHERE used < limit RETURNING)
  async consumeEmailQuota(tenantId) {
    const sub = subscriptions.get(tenantId);
    if (!sub || !sub.active) return { allowed: false, reason: 'inactive_plan' };
    if (sub.emailUsed >= sub.emailLimit) return { allowed: false, reason: 'quota_exceeded' };
    sub.emailUsed += 1;
    return { allowed: true };
  },
  async refundEmailQuota(tenantId) {
    const sub = subscriptions.get(tenantId);
    if (sub && sub.emailUsed > 0) sub.emailUsed -= 1;
  },
};

/* ------------------------------------------------------------------ */
/* Serviço de e-mail (SMTP)                                            */
/* ------------------------------------------------------------------ */

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT ?? 587),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  pool: true,
  connectionTimeout: 10_000,
  socketTimeout: 15_000,
});

// Remetente fixo: nunca vem da requisição
async function sendMail({ to, subject, html, text }) {
  return transporter.sendMail({ from: process.env.MAIL_FROM, to, subject, html, text });
}

/* ------------------------------------------------------------------ */
/* Template: validação de variáveis e renderização                     */
/* ------------------------------------------------------------------ */

const MAX_VAR_LENGTH = 2_000;
const MAX_VARS = 50;

function validateVariables(variables, allowedVariables) {
  const entries = Object.entries(variables ?? {});
  if (entries.length > MAX_VARS) {
    throw httpError(422, 'Número de variáveis acima do permitido.');
  }

  const allowed = new Set(allowedVariables);
  const clean = Object.create(null);

  for (const [key, value] of entries) {
    if (!allowed.has(key)) throw httpError(422, `Variável não permitida: ${key}`);
    if (!['string', 'number', 'boolean'].includes(typeof value)) {
      throw httpError(422, `Tipo inválido para a variável: ${key}`);
    }
    if (typeof value === 'string' && value.length > MAX_VAR_LENGTH) {
      throw httpError(422, `Valor muito longo para a variável: ${key}`);
    }
    clean[key] = value;
  }
  return clean;
}

function renderTemplate(template, variables) {
  // {{var}} escapa HTML por padrão. Evite {{{var}}} com dados de usuários.
  const render = (src) => Handlebars.compile(src)(variables);

  return {
    subject: render(template.subject).replace(/[\r\n]+/g, ' ').trim(), // evita header injection
    html: render(template.htmlBody),
    text: template.textBody ? render(template.textBody) : undefined,
  };
}

/* ------------------------------------------------------------------ */
/* Rota: POST /api/v1/emails/send                                      */
/* ------------------------------------------------------------------ */

const tenantLimiter = rateLimit({
  windowMs: 60_000,
  limit: 60,
  keyGenerator: (req) => `tenant:${req.auth.tenantId}`,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Limite de envios excedido. Tente novamente em instantes.' },
});

const sendEmailSchema = z.object({
  templateId: z.string().uuid(),
  to: z.string().trim().toLowerCase().email().max(254),
  variables: z.record(z.union([z.string(), z.number(), z.boolean()])).default({}),
});

const emailRouter = express.Router();

emailRouter.post('/send', tenantLimiter, async (req, res, next) => {
  try {
    const { tenantId, userId, permissions } = req.auth;

    if (!permissions.includes('email:send')) {
      throw httpError(403, 'Sem permissão para enviar e-mails.');
    }

    const parsed = sendEmailSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Dados inválidos.',
        details: parsed.error.issues.map((i) => ({
          campo: i.path.join('.'),
          mensagem: i.message,
        })),
      });
    }
    const { templateId, to, variables } = parsed.data;

    // Isolamento entre locatários: busca pelo par (tenantId, templateId)
    const template = await templateRepository.findByIdForTenant(tenantId, templateId);
    if (!template || !template.active) throw httpError(404, 'Template não encontrado.');

    const cleanVars = validateVariables(variables, template.allowedVariables);
    const { subject, html, text } = renderTemplate(template, cleanVars);

    // Cota do plano de assinatura
    const quota = await subscriptionService.consumeEmailQuota(tenantId);
    if (!quota.allowed) {
      if (quota.reason === 'inactive_plan') throw httpError(402, 'Assinatura inativa.');
      throw httpError(429, 'Cota mensal de e-mails do plano esgotada.');
    }

    try {
      const info = await sendMail({ to, subject, html, text });

      // Log sem as variáveis (podem conter dados pessoais)
      await emailLogRepository.create({
        tenantId,
        userId,
        templateId,
        recipient: to,
        status: 'sent',
        providerMessageId: info.messageId,
      });

      return res.status(202).json({ status: 'sent', messageId: info.messageId });
    } catch (mailErr) {
      await subscriptionService.refundEmailQuota(tenantId).catch(() => {});
      await emailLogRepository
        .create({ tenantId, userId, templateId, recipient: to, status: 'failed' })
        .catch(() => {});

      console.error('[email] falha no envio', { tenantId, templateId, code: mailErr.code });
      throw httpError(502, 'Não foi possível enviar o e-mail no momento.');
    }
  } catch (err) {
    next(err);
  }
});

/* ------------------------------------------------------------------ */
/* Aplicação                                                           */
/* ------------------------------------------------------------------ */

const app = express();
app.use(helmet());
app.use(express.json({ limit: '50kb' }));

app.use('/api/v1/emails', authenticate, emailRouter);

// Tratador de erros central: não vaza detalhes internos
app.use((err, _req, res, _next) => {
  const status = err.status ?? 500;
  if (!err.status) console.error(err);
  res.status(status).json({ error: status === 500 ? 'Erro interno.' : err.message });
});

app.listen(process.env.PORT ?? 3000, () => {
  console.log(`API ouvindo na porta ${process.env.PORT ?? 3000}`);
});