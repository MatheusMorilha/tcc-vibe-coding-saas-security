'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const PDFDocument = require('pdfkit');

const router = express.Router();

/*
 * Rate limit específico para geração de PDFs.
 * Evita que um usuário consuma excessivamente CPU/memória.
 */
const pdfRateLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

/*
 * Estas funções representam componentes já existentes da aplicação.
 *
 * db: camada de acesso ao banco (Prisma, Sequelize, Knex etc.)
 * authenticate: middleware que valida o JWT/sessão.
 * authorize: middleware que verifica permissões.
 */
const {
  db,
  authenticate,
  authorize
} = require('../dependencies');

/*
 * Escapa valores destinados ao PDF.
 *
 * PDFKit não interpreta HTML aqui, mas a normalização continua sendo
 * útil para evitar que dados arbitrários do banco controlem a estrutura
 * do relatório.
 */
function safeText(value, maxLength = 500) {
  if (value === null || value === undefined) {
    return '';
  }

  return String(value)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .slice(0, maxLength);
}

function formatCurrency(value, currency = 'BRL') {
  const amount = Number(value);

  if (!Number.isFinite(amount)) {
    return '0,00';
  }

  return new Intl.NumberFormat('pt-BR', {
    style: 'currency',
    currency
  }).format(amount);
}

function formatDate(value) {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return '';
  }

  return new Intl.DateTimeFormat('pt-BR').format(date);
}

/**
 * GET /api/invoices/:invoiceId/pdf
 *
 * Retorna a fatura do tenant do usuário autenticado em PDF.
 */
router.get(
  '/api/invoices/:invoiceId/pdf',
  authenticate,
  authorize('invoice:read'),
  pdfRateLimit,
  async (req, res, next) => {
    try {
      const { invoiceId } = req.params;

      /*
       * Validação de formato.
       *
       * Neste exemplo usamos UUID. Se o sistema utilizar IDs numéricos,
       * substitua por uma validação numérica estrita.
       */
      const uuidRegex =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

      if (!uuidRegex.test(invoiceId)) {
        return res.status(400).json({
          error: 'INVALID_INVOICE_ID'
        });
      }

      /*
       * CRÍTICO PARA MULTITENANCY:
       *
       * tenantId vem do usuário autenticado.
       * Não usamos req.query.tenantId, req.body.tenantId etc.
       *
       * A consulta deve verificar simultaneamente:
       *
       *   invoice.id === invoiceId
       *   invoice.tenantId === req.user.tenantId
       *
       * Isso impede que um usuário de uma empresa consulte a fatura
       * pertencente a outra empresa.
       */
      const tenantId = req.user.tenantId;

      if (!tenantId) {
        return res.status(403).json({
          error: 'TENANT_CONTEXT_REQUIRED'
        });
      }

      const invoice = await db.invoice.findFirst({
        where: {
          id: invoiceId,
          tenantId: tenantId
        },

        /*
         * Buscar somente os campos necessários para o relatório.
         * Evita exposição acidental de dados internos/sensíveis.
         */
        select: {
          id: true,
          number: true,
          issueDate: true,
          dueDate: true,
          status: true,
          currency: true,
          subtotal: true,
          tax: true,
          total: true,

          customer: {
            select: {
              name: true,
              document: true,
              email: true
            }
          },

          items: {
            select: {
              description: true,
              quantity: true,
              unitPrice: true,
              total: true
            }
          }
        }
      });

      /*
       * Retornar 404 tanto para uma fatura inexistente quanto para uma
       * fatura pertencente a outro tenant.
       *
       * Isso evita revelar se determinado ID existe em outro tenant.
       */
      if (!invoice) {
        return res.status(404).json({
          error: 'INVOICE_NOT_FOUND'
        });
      }

      /*
       * O PDF é gerado em memória neste exemplo.
       *
       * Para PDFs muito grandes, prefira streaming ou geração assíncrona
       * para evitar consumo excessivo de memória.
       */
      const pdf = new PDFDocument({
        size: 'A4',
        margin: 50,
        info: {
          Title: `Fatura ${safeText(invoice.number, 100)}`,
          Author: 'Plataforma SaaS',
          Subject: 'Relatório de fatura'
        }
      });

      /*
       * Não aceitar nome de arquivo enviado pelo cliente.
       * O nome é construído a partir de dados previamente validados.
       */
      const safeInvoiceNumber = safeText(invoice.number, 50)
        .replace(/[^a-zA-Z0-9._-]/g, '_');

      const filename = `fatura-${safeInvoiceNumber || invoice.id}.pdf`;

      res.status(200);

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${filename}"`
      );

      /*
       * Evita cache compartilhado de documentos potencialmente
       * confidenciais.
       */
      res.setHeader('Cache-Control', 'private, no-store, max-age=0');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('X-Content-Type-Options', 'nosniff');

      pdf.pipe(res);

      /*
       * Cabeçalho
       */
      pdf
        .fontSize(20)
        .font('Helvetica-Bold')
        .text('FATURA', {
          align: 'center'
        });

      pdf.moveDown();

      pdf
        .fontSize(11)
        .font('Helvetica')
        .text(`Número: ${safeText(invoice.number, 100)}`)
        .text(`Emissão: ${formatDate(invoice.issueDate)}`)
        .text(`Vencimento: ${formatDate(invoice.dueDate)}`)
        .text(`Status: ${safeText(invoice.status, 50)}`);

      pdf.moveDown();

      /*
       * Cliente
       */
      pdf
        .fontSize(14)
        .font('Helvetica-Bold')
        .text('Cliente');

      pdf
        .fontSize(10)
        .font('Helvetica')
        .text(`Nome: ${safeText(invoice.customer?.name)}`)
        .text(`Documento: ${safeText(invoice.customer?.document)}`)
        .text(`E-mail: ${safeText(invoice.customer?.email)}`);

      pdf.moveDown();

      /*
       * Itens
       */
      pdf
        .fontSize(14)
        .font('Helvetica-Bold')
        .text('Itens');

      pdf.moveDown(0.5);

      invoice.items.forEach((item, index) => {
        pdf
          .fontSize(10)
          .font('Helvetica-Bold')
          .text(`${index + 1}. ${safeText(item.description, 300)}`);

        pdf
          .font('Helvetica')
          .text(`Quantidade: ${Number(item.quantity) || 0}`)
          .text(
            `Valor unitário: ${formatCurrency(
              item.unitPrice,
              invoice.currency
            )}`
          )
          .text(
            `Total: ${formatCurrency(
              item.total,
              invoice.currency
            )}`
          );

        pdf.moveDown(0.5);
      });

      pdf.moveDown();

      /*
       * Totais
       */
      pdf
        .fontSize(11)
        .font('Helvetica')
        .text(
          `Subtotal: ${formatCurrency(
            invoice.subtotal,
            invoice.currency
          )}`,
          {
            align: 'right'
          }
        )
        .text(
          `Impostos: ${formatCurrency(
            invoice.tax,
            invoice.currency
          )}`,
          {
            align: 'right'
          }
        );

      pdf
        .fontSize(14)
        .font('Helvetica-Bold')
        .text(
          `Total: ${formatCurrency(
            invoice.total,
            invoice.currency
          )}`,
          {
            align: 'right'
          }
        );

      pdf.end();
    } catch (error) {
      /*
       * Não devolver stack trace ou detalhes internos ao cliente.
       * O middleware global de erros deve registrar o erro internamente.
       */
      return next(error);
    }
  }
);

module.exports = router;
