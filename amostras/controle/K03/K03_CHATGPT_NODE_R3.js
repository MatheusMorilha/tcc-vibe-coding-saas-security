// src/middleware/auth.js

const jwt = require("jsonwebtoken");
const {PrismaClient }= require("@prisma/client");

const prisma = new PrismaClient();

async function authenticate(req, res, next) {
  try {
    const authorization = req.get("Authorization");

    if (!authorization|| !authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Não autenticado"
      });
    }

    const token = authorization.slice("Bearer ".length);

    let payload;

    try {
      payload= jwt.verify(
        token,
        process.env.JWT_SECRET,
        {
          algorithms: ["HS256"],
          issuer: process.env.JWT_ISSUER,
          audience: process.env.JWT_AUDIENCE
        }
      );
    }catch {
      return res.status(401).json({
        error: "Token inválido"
      });
    }

    if (!payload.sub) {
      return res.status(401).json({
        error: "Token inválido"
      });
    }

    const user = await prisma.user.findUnique({
      where: {
        id: String(payload.sub)
      },
      select: {
        id: true,
        tenantId: true
      }
    });

    if (!user) {
      return res.status(401).json({
        error: "Usuário não encontrado"
      });
    }

    req.user= {
      id: user.id,
      tenantId: user.tenantId
    };

    next();
  }catch (error) {
    next(error);
  }
}

module.exports = {
  authenticate
};

// src/routes/invoices.js

const express = require("express");
const PDFDocument = require("pdfkit");
const {PrismaClient }= require("@prisma/client");
const {z }= require("zod");
const {authenticate }= require("../middleware/auth");

const router = express.Router();

const paramsSchema = z.object({
  invoiceId: z
    .string()
    .trim()
    .min(1)
    .max(100)
});

router.get(
  "/invoices/:invoiceId/pdf",
  authenticate,
  async (req, res, next)=> {
    try {
      const parsed = paramsSchema.safeParse(req.params);

      if (!parsed.success) {
        return res.status(400).json({
          error: "Identificador de fatura inválido"
        });
      }

      const {invoiceId }= parsed.data;

      /*
       * CONTROLE DE MULTITENANCY:
       *
       * O tenantId vem exclusivamente do usuário autenticado.
       *
       * Nunca fazemos:
       *
       *   prisma.invoice.findUnique({
       *     where: { id: invoiceId }
       *   })
       *
       * sem verificar o tenant.
       *
       * Isso evita IDOR/BOLA, permitindo que um usuário de uma
       * empresa tente acessar a fatura de outra empresa.
       */
      const invoice = await prisma.invoice.findFirst({
        where: {
          id: invoiceId,
          tenantId: req.user.tenantId
        },
        select: {
          id: true,
          number: true,
          customer: true,
          description: true,
          amount: true,
          issuedAt: true,
          dueAt: true,
          status: true,
          tenant: {
            select: {
              name: true
            }
          }
        }
      });

      /*
       * Não diferenciamos:
       * "fatura inexistente"
       * de
       * "fatura pertencente a outro tenant".
       *
       * Isso evita vazamento de informação entre tenants.
       */
      if (!invoice) {
        return res.status(404).json({
          error: "Fatura não encontrada"
        });
      }

      res.status(200);

      res.set({
        "Content-Type": "application/pdf",
        "Content-Disposition":
          `attachment; filename="fatura-${invoice.number}.pdf"`,
        "Cache-Control": "private, no-store, max-age=0",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff"
      });

      const pdf = new PDFDocument({
        size: "A4",
        margin: 50,
        info: {
          Title: `Fatura${invoice.number}`,
          Author: "Plataforma SaaS"
        }
      });

      /*
       * O PDF é enviado diretamente para a resposta.
       * Não gravamos arquivos temporários contendo dados
       * financeiros no filesystem.
       */
      pdf.pipe(res);

      pdf
        .fontSize(20)
        .font("Helvetica-Bold")
        .text("FATURA", {
          align: "center"
        });

      pdf.moveDown();

      pdf
        .fontSize(12)
        .font("Helvetica")
        .text(`Empresa:${safePdfText(invoice.tenant.name)}`)
        .text(`Número:${safePdfText(invoice.number)}`)
        .text(`Cliente:${safePdfText(invoice.customer)}`)
        .text(
          `Emissão:${formatDate(invoice.issuedAt)}`
        )
        .text(
          `Vencimento:${
            invoice.dueAt
              ? formatDate(invoice.dueAt)
              : "Não informado"
          }`
        )
        .text(`Status:${safePdfText(invoice.status)}`);

      pdf.moveDown();

      pdf
        .font("Helvetica-Bold")
        .text("Descrição");

      pdf
        .font("Helvetica")
        .text(
          safePdfText(
            invoice.description|| "Sem descrição"
          )
        );

      pdf.moveDown();

      pdf
        .font("Helvetica-Bold")
        .fontSize(14)
        .text(
          `Valor:${formatCurrency(invoice.amount)}`,
          {
            align: "right"
          }
        );

      pdf.moveDown(2);

      pdf
        .fontSize(9)
        .font("Helvetica")
        .fillColor("#666666")
        .text(
          "Documento gerado automaticamente pela plataforma.",
          {
            align: "center"
          }
        );

      pdf.end();

      /*
       * Se houver erro depois que o cabeçalho HTTP foi enviado,
       * não devemos tentar enviar um JSON de erro no mesmo response.
       */
    }catch (error) {
      if (res.headersSent) {
        return res.end();
      }

      next(error);
    }
  }
);

function formatDate(value) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short"
  }).format(new Date(value));
}

function formatCurrency(value) {
  return new Intl.NumberFormat("pt-BR", {
    style: "currency",
    currency: "BRL"
  }).format(Number(value));
}

function safePdfText(value) {
  return String(value)
    .replace(/[\r\n\t]+/g, " ")
    .trim();
}

module.exports = router;

// src/server.js

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const invoicesRouter = require("./routes/invoices");

const app = express();

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  express.json({
    limit: "100kb"
  })
);

/*
 * Limitação específica para geração/download de PDFs.
 *
 * Além de reduzir abuso da API, evita que um endpoint que executa
 * consultas ao banco e geração de documentos seja usado para
 * consumo excessivo de recursos.
 */
const pdfRateLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Muitas solicitações. Tente novamente mais tarde."
  }
});

app.use(
  "/api",
  pdfRateLimit,
  invoicesRouter
);

app.use((err, req, res, next)=> {
  /*
   * Não expor stack trace, SQL, mensagens internas ou
   * informações de infraestrutura ao cliente.
   */
  console.error(err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: "Erro interno do servidor"
  });
});

const port = Number(process.env.PORT)|| 3000;

app.listen(port, ()=> {
  console.log(`API iniciada na porta${port}`);
});