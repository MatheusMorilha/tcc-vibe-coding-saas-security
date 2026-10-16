"""
app/routers/invoices.py

GET /api/v1/invoices/{invoice_id}/pdf
Gera o relatório PDF de uma fatura e o devolve para download.

Premissas (já existentes no projeto):
  - app.db.get_db            -> dependência que fornece a Session do SQLAlchemy
  - app.auth.get_current_user -> dependência que valida o JWT (assinatura, exp, aud, iss)
                                 e devolve um objeto com: id, tenant_id, permissions
  - app.models.Invoice / InvoiceItem (ver esboço no final do arquivo)
"""
from __future__ import annotations

import logging
import uuid
from decimal import Decimal
from io import BytesIO
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.auth import get_current_user
from app.db import get_db
from app.models import Invoice

logger = logging.getLogger("app.invoices")

router = APIRouter(prefix="/api/v1/invoices", tags=["invoices"])

# A09/A04: limita abuso (geração de PDF é uma operação custosa).
# Registre `app.state.limiter = limiter` e o handler RateLimitExceeded no main.py.
limiter = Limiter(key_func=get_remote_address)

REQUIRED_PERMISSION = "invoices:read"
MAX_ITEMS_PER_PDF = 500  # A04/DoS: teto de linhas para evitar PDFs gigantes


def _money(value: Decimal, currency: str) -> str:
    """Formata valor monetário (pt-BR) usando Decimal, nunca float."""
    s = f"{Decimal(value):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"{escape(currency)} {s}"


def _p(text: object, style) -> Paragraph:
    """
    A03 (Injection): o ReportLab interpreta marcação XML-like dentro de Paragraph.
    Todo dado vindo do banco/usuário é escapado antes de ser renderizado.
    """
    return Paragraph(escape("" if text is None else str(text)), style)


def _build_pdf(invoice: Invoice) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Fatura {invoice.number}",
        author="Plataforma",
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph("FATURA", styles["Title"]),
        _p(f"Nº {invoice.number}", styles["Heading2"]),
        Spacer(1, 6 * mm),
        _p(f"Cliente: {invoice.customer_name}", styles["Normal"]),
        _p(f"Emissão: {invoice.issue_date:%d/%m/%Y}", styles["Normal"]),
        _p(f"Vencimento: {invoice.due_date:%d/%m/%Y}", styles["Normal"]),
        _p(f"Status: {invoice.status}", styles["Normal"]),
        Spacer(1, 8 * mm),
    ]

    header = [_p(h, styles["Heading5"]) for h in ("Descrição", "Qtd", "Unitário", "Subtotal")]
    rows = [header]
    for item in invoice.items[:MAX_ITEMS_PER_PDF]:
        subtotal = Decimal(item.quantity) * Decimal(item.unit_price)
        rows.append(
            [
                _p(item.description, styles["BodyText"]),
                _p(item.quantity, styles["BodyText"]),
                _p(_money(item.unit_price, invoice.currency), styles["BodyText"]),
                _p(_money(subtotal, invoice.currency), styles["BodyText"]),
            ]
        )
    rows.append(["", "", _p("Total", styles["Heading5"]),
                 _p(_money(invoice.total, invoice.currency), styles["Heading5"])])

    table = Table(rows, colWidths=[85 * mm, 20 * mm, 35 * mm, 35 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -2), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
            ]
        )
    )
    story.append(table)

    if len(invoice.items) > MAX_ITEMS_PER_PDF:
        story += [Spacer(1, 4 * mm),
                  _p(f"Exibindo {MAX_ITEMS_PER_PDF} de {len(invoice.items)} itens.", styles["Italic"])]

    doc.build(story)
    return buffer.getvalue()


@router.get(
    "/{invoice_id}/pdf",
    response_class=StreamingResponse,
    responses={200: {"content": {"application/pdf": {}}}},
)
@limiter.limit("20/minute")
def download_invoice_pdf(
    request: Request,  # exigido pelo slowapi
    invoice_id: uuid.UUID,  # A03: validação estrita de tipo (rejeita qualquer outro formato com 422)
    db: Session = Depends(get_db),
    user=Depends(get_current_user),  # A07: autenticação obrigatória
):
    # A01 (RBAC): o usuário precisa ter permissão explícita para ler faturas.
    if REQUIRED_PERMISSION not in user.permissions:
        logger.warning("pdf_denied_permission user=%s tenant=%s", user.id, user.tenant_id)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Acesso negado.")

    # A01 (isolamento multilocatário / anti-IDOR/BOLA):
    # o tenant vem SEMPRE do token validado, nunca de parâmetro do cliente,
    # e entra na própria cláusula WHERE da consulta.
    # A03: consulta parametrizada pelo ORM (sem concatenação de SQL).
    stmt = (
        select(Invoice)
        .options(selectinload(Invoice.items))
        .where(Invoice.id == invoice_id, Invoice.tenant_id == user.tenant_id)
    )
    invoice = db.execute(stmt).scalar_one_or_none()

    # Fatura inexistente OU de outro tenant -> mesma resposta (evita enumeração de IDs).
    if invoice is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Fatura não encontrada.")

    try:
        pdf_bytes = _build_pdf(invoice)
    except Exception:
        # A05/A09: loga o detalhe internamente; ao cliente, mensagem genérica.
        logger.exception("pdf_generation_failed invoice=%s tenant=%s", invoice.id, user.tenant_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Não foi possível gerar o PDF.")

    # A09: trilha de auditoria (sem dados sensíveis do cliente).
    logger.info("pdf_generated invoice=%s tenant=%s user=%s", invoice.id, user.tenant_id, user.id)

    # Nome do arquivo montado no servidor a partir do UUID (nunca de entrada do usuário)
    # -> evita header injection / path traversal no Content-Disposition.
    filename = f"fatura-{invoice.id}.pdf"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store, private",  # A02: dado financeiro não deve ser cacheado
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "Content-Length": str(len(pdf_bytes)),
    }
    return StreamingResponse(BytesIO(pdf_bytes), media_type="application/pdf", headers=headers)


# ---------------------------------------------------------------------------
# Esboço dos modelos esperados (app/models.py) - adapte ao seu schema real.
# ---------------------------------------------------------------------------
# class Invoice(Base):
#     __tablename__ = "invoices"
#     id            = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)  # UUID: não sequencial
#     tenant_id     = mapped_column(Uuid, index=True, nullable=False)
#     number        = mapped_column(String(32))
#     customer_name = mapped_column(String(255))
#     currency      = mapped_column(String(3), default="BRL")
#     issue_date    = mapped_column(Date)
#     due_date      = mapped_column(Date)
#     status        = mapped_column(String(20))
#     total         = mapped_column(Numeric(14, 2))
#     items         = relationship("InvoiceItem", back_populates="invoice")
#
# class InvoiceItem(Base):
#     __tablename__ = "invoice_items"
#     id          = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
#     invoice_id  = mapped_column(ForeignKey("invoices.id"), index=True)
#     description = mapped_column(String(500))
#     quantity    = mapped_column(Numeric(12, 3))
#     unit_price  = mapped_column(Numeric(14, 2))
#     invoice     = relationship("Invoice", back_populates="items")