'use strict';

const express = require('express');
const PDFDocument = require('pdfkit');

const router = express.Router();

/*
 * Espera-se que req.user seja preenchido pelo middleware de autenticação:
 * {
 *   id: '...',
 *   tenantId: '...'
 * }
 *
 * E que req.db seja um cliente/conexão com suporte a queries parametrizadas.
 */

router.get(
  '/invoices/:invoiceId/pdf',
  requireAuthenticatedUser,
  validateInvoiceId,
  async (req, res, next) => {
    const { invoiceId } = req.params;
    const { tenantId } = req.user;

    try {
      /*
       * IMPORTANTE:
       * tenant_id faz parte do filtro. Isso impede que um usuário de uma
       * empresa consulte a fatura de outro tenant mesmo que conheça o ID.
       */
      const invoiceResult = await req.db.query(
        `
        SELECT
          i.id,
          i.number,
          i.issue_date,
          i.due_date,
          i.status,
          i.subtotal,
          i.tax,
          i.total,
          c.name AS customer_name,
          c.document AS customer_document
        FROM invoices i
        INNER JOIN customers c
          ON c.id = i.customer_id
         AND c.tenant_id = i.tenant_id
        WHERE i.id = $1
          AND i.tenant_id = $2
        LIMIT 1
        `,
        [invoiceId, tenantId]
      );

      if (invoiceResult.rows.length === 0) {
        // Não revela se a fatura existe em outro tenant.
        return res.status(404).json({
          error: 'Fatura não encontrada'
        });
      }

      const invoice = invoiceResult.rows[0];

      /*
       * Busca os itens usando novamente tenant_id.
       * Não confiar apenas no relacionamento por invoice_id.
       */
      const itemsResult = await req.db.query(
        `
        SELECT
          description,
          quantity,
          unit_price,
          total
        FROM invoice_items
        WHERE invoice_id = $1
          AND tenant_id = $2
        ORDER BY id ASC
        `,
        [invoiceId, tenantId]
      );

      // Headers para download e prevenção de interpretação indevida.
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="fatura-${invoice.number}.pdf"`
      );
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Cache-Control', 'private, no-store');

      const pdf = new PDFDocument({
        size: 'A4',
        margin: 50,
        info: {
          Title: `Fatura ${invoice.number}`,
          Author: 'Plataforma SaaS'
        }
      });

      pdf.on('error', next);
      pdf.pipe(res);

      pdf
        .fontSize(20)
        .text('FATURA', { align: 'center' })
        .moveDown();

      pdf
        .fontSize(11)
        .text(`Número: ${safeText(invoice.number)}`)
        .text(`Emissão: ${formatDate(invoice.issue_date)}`)
        .text(`Vencimento: ${formatDate(invoice.due_date)}`)
        .text(`Status: ${safeText(invoice.status)}`)
        .moveDown();

      pdf
        .fontSize(13)
        .text('Cliente')
        .fontSize(11)
        .text(`Nome: ${safeText(invoice.customer_name)}`)
        .text(`Documento: ${safeText(invoice.customer_document)}`)
        .moveDown();

      pdf.fontSize(13).text('Itens').moveDown(0.5);

      pdf.fontSize(10);

      for (const item of itemsResult.rows) {
        pdf
          .text(
            `${safeText(item.description)} | ` +
            `Qtd: ${formatNumber(item.quantity)} | ` +
            `Unitário: ${formatMoney(item.unit_price)} | ` +
            `Total: ${formatMoney(item.total)}`
          )
          .moveDown(0.3);
      }

      pdf.moveDown();

      pdf
        .fontSize(11)
        .text(`Subtotal: ${formatMoney(invoice.subtotal)}`)
        .text(`Impostos: ${formatMoney(invoice.tax)}`)
        .fontSize(14)
        .text(`Total: ${formatMoney(invoice.total)}`);

      pdf.end();
    } catch (error) {
      /*
       * Não enviar stack trace ou detalhes internos para o cliente.
       * O middleware global de erros deve registrar o erro internamente.
       */
      next(error);
    }
  }
);

function requireAuthenticatedUser(req, res, next) {
  if (!req.user || !req.user.id || !req.user.tenantId) {
    return res.status(401).json({
      error: 'Não autenticado'
    });
  }

  next();
}

function validateInvoiceId(req, res, next) {
  /*
   * Exemplo usando UUID. Se a aplicação usar IDs numéricos, substitua
   * pela validação correspondente.
   */
  const uuidRegex =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  if (!uuidRegex.test(req.params.invoiceId)) {
    return res.status(400).json({
      error: 'ID de fatura inválido'
    });
  }

  next();
}

function safeText(value) {
  if (value === null || value === undefined) {
    return '';
  }

  return String(value);
}

function formatDate(value) {
  if (!value) {
    return '';

  }

  return new Intl.DateTimeFormat('pt-BR').format(new Date(value));
}

function formatNumber(value) {
  return new Intl.NumberFormat('pt-BR').format(Number(value));
}

function formatMoney(value) {
  return new Intl.NumberFormat('pt-BR', {
    style: 'currency',
    currency: 'BRL'
  }).format(Number(value));
}

module.exports = router;
