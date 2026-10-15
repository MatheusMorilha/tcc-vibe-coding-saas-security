"""
app/routers/invoices.py

Rota de geração de relatório PDF de fatura (SaaS multilocatário).

Pressupostos sobre o projeto existente (ajuste os imports):
  - get_db: dependência que fornece a Session do SQLAlchemy.
  - get_current_user: dependência que valida o token e retorna o usuário
    autenticado, com os atributos `id` e `tenant_id`.
  - Modelos Invoice e InvoiceItem com coluna `tenant_id` em Invoice.
"""
import logging
import re
from decimal import Decimal
from io import BytesIO
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException, Response, status
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

# --- imports do seu projeto (ajuste os caminhos) -----------------------------
from app.auth import get_current_user
from app.database import get_db
from app.models import Invoice

# -----------------------------------------------------------------------------

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/invoices", tags=["invoices"])

MAX_ITEMS_PER_REPORT = 2000  # evita PDFs gigantes / consumo excessivo de memória


def _money(value: Decimal | None, currency: str = "BRL") -> str:
    """Formata valores monetários no padrão brasileiro (1.234,56)."""
    value = Decimal(value or 0)
    text = f"{value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"{currency} {text}"


def _safe(text: object) -> str:
    """Escapa texto vindo do banco antes de enviá-lo ao Paragraph do ReportLab
    (que interpreta marcação XML-like), evitando quebra/injeção de marcação."""
    return escape(str(text if text is not None else ""))


def _build_invoice_pdf(invoice: Invoice) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title=f"Fatura {invoice.number}",
        author="Plataforma",
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph(f"Fatura nº {_safe(invoice.number)}", styles["Title"]),
        Spacer(1, 6 * mm),
        Paragraph(f"<b>Cliente:</b> {_safe(invoice.customer_name)}", styles["Normal"]),
        Paragraph(f"<b>Emissão:</b> {invoice.issue_date:%d/%m/%Y}", styles["Normal"]),
        Paragraph(f"<b>Vencimento:</b> {invoice.due_date:%d/%m/%Y}", styles["Normal"]),
        Paragraph(f"<b>Status:</b> {_safe(invoice.status)}", styles["Normal"]),
        Spacer(1, 8 * mm),
    ]

    currency = invoice.currency or "BRL"
    rows = [["Descrição", "Qtd.", "Preço unit.", "Subtotal"]]
    total = Decimal("0")
    for item in invoice.items:
        subtotal = Decimal(item.quantity) * Decimal(item.unit_price)
        total += subtotal
        rows.append(
            [
                Paragraph(_safe(item.description), styles["Normal"]),
                f"{item.quantity}",
                _money(item.unit_price, currency),
                _money(subtotal, currency),
            ]
        )
    rows.append(["", "", "Total", _money(total, currency)])

    table = Table(rows, colWidths=[85 * mm, 20 * mm, 35 * mm, 35 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -2), 0.25, colors.lightgrey),
                ("FONTNAME", (2, -1), (-1, -1), "Helvetica-Bold"),
                ("LINEABOVE", (2, -1), (-1, -1), 0.75, colors.black),
            ]
        )
    )
    story.append(table)

    doc.build(story)
    return buffer.getvalue()


@router.get(
    "/{invoice_id}/report.pdf",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}}}, 404: {"description": "Fatura não encontrada"}},
)
def download_invoice_pdf(
    invoice_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Response:
    # Isolamento de tenant: o filtro por tenant_id faz parte da consulta,
    # e o valor vem do usuário autenticado (nunca de parâmetro do cliente).
    stmt = (
        select(Invoice)
        .options(selectinload(Invoice.items))
        .where(
            Invoice.id == invoice_id,
            Invoice.tenant_id == current_user.tenant_id,
        )
    )
    invoice = db.execute(stmt).scalar_one_or_none()

    # 404 (e não 403) para não revelar a existência de faturas de outros tenants.
    if invoice is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Fatura não encontrada")

    if len(invoice.items) > MAX_ITEMS_PER_REPORT:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Fatura excede o limite de itens para geração de relatório",
        )

    pdf_bytes = _build_invoice_pdf(invoice)

    # Nome de arquivo sanitizado (evita header injection / caracteres inválidos).
    safe_number = re.sub(r"[^A-Za-z0-9_-]", "_", str(invoice.number))
    filename = f"fatura_{safe_number}.pdf"

    logger.info(
        "invoice_pdf_generated tenant_id=%s user_id=%s invoice_id=%s",
        current_user.tenant_id,
        current_user.id,
        invoice.id,
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "private, no-store",  # dados de um tenant não devem ser cacheados
            "X-Content-Type-Options": "nosniff",
        },
    )