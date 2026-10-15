require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const { authenticate } = require('./middleware/auth');
const emailRoutes = require('./modules/email/email.routes');

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '50kb' })); // limita o tamanho do payload

app.use('/api/v1/emails', authenticate, emailRoutes);

// Tratador de erros genérico: nunca vaza detalhes internos
app.use((err, _req, res, _next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'JSON inválido.' });
  }
  console.error('[unhandled]', err.message);
  res.status(500).json({ error: 'Erro interno.' });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`API ouvindo na porta ${port}`));

const jwt = require('jsonwebtoken');

function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Não autenticado.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
    });

    if (!payload.sub || !payload.tenantId) {
      return res.status(401).json({ error: 'Token inválido.' });
    }

    req.auth = {
      userId: payload.sub,
      tenantId: payload.tenantId,
      permissions: payload.permissions || [],
    };
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.auth.permissions.includes(permission)) {
      return res.status(403).json({ error: 'Sem permissão para esta operação.' });
    }
    next();
  };
}

module.exports = { authenticate, requirePermission };

// Substitua pela sua camada de dados (pg, Prisma, Knex etc.)
async function findActiveTenant(tenantId) {
  // SELECT t.id, t.name, t.support_email, s.status, s.plan
  //   FROM tenants t
  //   JOIN subscriptions s ON s.tenant_id = t.id
  //  WHERE t.id = $1 AND s.status = 'active'
  return { id: tenantId, name: 'Empresa Exemplo', supportEmail: 'contato@exemplo.com', plan: 'pro' };
}

module.exports = { findActiveTenant };

// UPDATE email_usage
//    SET used = used + 1
//  WHERE tenant_id = $1
//    AND period = date_trunc('month', now())
//    AND used < (SELECT monthly_email_limit FROM plans WHERE id = $2)
// RETURNING used;
// -> se nenhuma linha for afetada, a cota do plano foi excedida.
async function reserveEmailQuota(tenantId, plan) {
  return true;
}

async function releaseEmailQuota(tenantId) {
  // UPDATE email_usage SET used = used - 1 WHERE tenant_id = $1 AND ...
}

module.exports = { reserveEmailQuota, releaseEmailQuota };

const fs = require('node:fs');
const path = require('node:path');
const Handlebars = require('handlebars');
const { z } = require('zod');

// Só aceita links https (bloqueia javascript:, data: etc.)
const httpsUrl = z
  .string()
  .url()
  .max(2048)
  .refine((u) => new URL(u).protocol === 'https:', 'A URL deve usar https.');

const shortText = (max = 100) =>
  z.string().trim().min(1).max(max).regex(/^[^\r\n]*$/, 'Quebras de linha não são permitidas.');

const definitions = {
  welcome: {
    file: 'welcome.hbs',
    subject: 'Bem-vindo(a) à {{tenant.name}}, {{userName}}!',
    schema: z.object({
      userName: shortText(80),
      loginUrl: httpsUrl,
    }).strict(),
  },
  'invite-user': {
    file: 'invite-user.hbs',
    subject: '{{inviterName}} convidou você para a {{tenant.name}}',
    schema: z.object({
      inviterName: shortText(80),
      inviteUrl: httpsUrl,
      expiresInHours: z.number().int().min(1).max(168),
    }).strict(),
  },
};

// Pré-compila no boot: falha rápido se algum template estiver quebrado
const registry = new Map();
for (const [name, def] of Object.entries(definitions)) {
  const source = fs.readFileSync(path.join(__dirname, 'templates', def.file), 'utf8');
  registry.set(name, {
    schema: def.schema,
    renderSubject: Handlebars.compile(def.subject),
    renderBody: Handlebars.compile(source), // escape HTML ativo por padrão
  });
}

module.exports = {
  getTemplate: (name) => registry.get(name),
  templateNames: [...registry.keys()],
};

const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  pool: true,
  connectionTimeout: 10_000,
  greetingTimeout: 10_000,
  socketTimeout: 15_000,
});

// Remove CR/LF e aspas para evitar injeção de cabeçalhos
const clean = (s) => String(s).replace(/[\r\n"<>]/g, ' ').trim();

// Versão texto simples (multipart/alternative melhora a entregabilidade)
const htmlToText = (html) =>
  html
    .replace(/<(br|\/p|\/h\d|\/div)\s*\/?>/gi, '\n')
    .replace(/<a [^>]*href="([^"]+)"[^>]*>(.*?)<\/a>/gi, '$2 ($1)')
    .replace(/<[^>]+>/g, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

async function sendTemplatedEmail({ tenant, to, template, variables }) {
  // `tenant` vem do servidor; o cliente não consegue sobrescrevê-lo
  const context = {
    ...variables,
    tenant: { name: tenant.name, supportEmail: tenant.supportEmail },
  };

  const subject = clean(template.renderSubject(context)).slice(0, 200);
  const html = template.renderBody(context);

  const info = await transporter.sendMail({
    from: { name: `${clean(tenant.name)}`, address: process.env.MAIL_FROM_ADDRESS },
    replyTo: tenant.supportEmail,
    to,
    subject,
    html,
    text: htmlToText(html),
  });

  return info.messageId;
}

module.exports = { sendTemplatedEmail };

const express = require('express');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

const { requirePermission } = require('../../middleware/auth');
const { getTemplate, templateNames } = require('./template.registry');
const { sendTemplatedEmail } = require('./email.service');
const { findActiveTenant } = require('../../repositories/tenant.repository');
const { reserveEmailQuota, releaseEmailQuota } = require('../../repositories/usage.repository');

const router = express.Router();

// Rate limit por tenant (e não por IP), para um tenant não degradar os demais
const limiter = rateLimit({
  windowMs: 60_000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `tenant:${req.auth.tenantId}`,
  message: { error: 'Muitas requisições. Tente novamente em instantes.' },
});

const bodySchema = z.object({
  to: z.string().trim().toLowerCase().email().max(254),
  template: z.string().min(1).max(64),
  variables: z.record(z.unknown()).default({}),
}).strict();

router.post(
  '/send',
  limiter,
  requirePermission('emails:send'),
  async (req, res, next) => {
    const { tenantId, userId } = req.auth;
    let quotaReserved = false;

    try {
      // 1) Validação do envelope
      const body = bodySchema.safeParse(req.body);
      if (!body.success) {
        return res.status(400).json({ error: 'Requisição inválida.', details: body.error.flatten().fieldErrors });
      }
      const { to, template: templateName, variables } = body.data;

      // 2) Template deve existir na allowlist
      const template = getTemplate(templateName);
      if (!template) {
        return res.status(400).json({ error: 'Template desconhecido.', available: templateNames });
      }

      // 3) Variáveis validadas contra o schema estrito do template
      const vars = template.schema.safeParse(variables);
      if (!vars.success) {
        return res.status(400).json({ error: 'Variáveis do template inválidas.', details: vars.error.flatten().fieldErrors });
      }

      // 4) Tenant com assinatura ativa (consulta sempre filtrada por tenantId do token)
      const tenant = await findActiveTenant(tenantId);
      if (!tenant) {
        return res.status(402).json({ error: 'Assinatura inativa ou inexistente.' });
      }

      // 5) Cota mensal do plano (reserva atômica)
      quotaReserved = await reserveEmailQuota(tenantId, tenant.plan);
      if (!quotaReserved) {
        return res.status(429).json({ error: 'Cota mensal de e-mails do plano excedida.' });
      }

      // 6) Envio
      const messageId = await sendTemplatedEmail({
        tenant,
        to,
        template,
        variables: vars.data,
      });

      // Log de auditoria sem PII nem conteúdo das variáveis
      console.info(JSON.stringify({
        event: 'email.sent', tenantId, userId, template: templateName, messageId,
      }));

      return res.status(202).json({ status: 'sent', messageId });
    } catch (err) {
      if (quotaReserved) {
        await releaseEmailQuota(tenantId).catch(() => {});
      }
      console.error(JSON.stringify({ event: 'email.failed', tenantId, userId, reason: err.code || err.message }));
      // Falha do provedor SMTP: erro de gateway, sem expor detalhes
      if (err.code && ['ECONNECTION', 'ETIMEDOUT', 'EAUTH', 'ESOCKET', 'EENVELOPE'].includes(err.code)) {
        return res.status(502).json({ error: 'Falha ao enviar o e-mail. Tente novamente.' });
      }
      return next(err);
    }
  }
);

module.exports = router;