from io import BytesIO
from datetime import date, datetime
from decimal import Decimal
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from app.database import get_db
from app.auth import get_current_user
from app.models import Invoice, User


router = APIRouter(prefix="/invoices", tags=["Invoices"])


def format_currency(value) -> str:
    """Formata valores monetários no padrão brasileiro."""
    value = Decimal(str(value or 0))
    formatted = f"{value:,.2f}"
    formatted = formatted.replace(",", "X")
    formatted = formatted.replace(".", ",")
    formatted = formatted.replace("X", ".")
    return f"R$ {formatted}"


def format_date(value) -> str:
    """Formata datas para exibição no relatório."""
    if isinstance(value, (date, datetime)):
        return value.strftime("%d/%m/%Y")
    return str(value or "-")


def generate_invoice_pdf(invoice: Invoice) -> bytes:
    """Gera o relatório PDF de uma fatura em memória."""
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"Fatura {invoice.number}",
        author="Plataforma SaaS",
    )

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="InvoiceTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            textColor=colors.HexColor("#1F4E79"),
            spaceAfter=20,
        )
    )

    styles.add(
        ParagraphStyle(
            name="RightAligned",
            parent=styles["Normal"],
            alignment=TA_RIGHT,
        )
    )

    elements = []

    # Cabeçalho do relatório
    elements.append(
        Paragraph("RELATÓRIO DE FATURA", styles["InvoiceTitle"])
    )

    elements.append(
        Paragraph(
            f"<b>Número:</b> {escape(str(invoice.number))}",
            styles["Normal"],
        )
    )

    elements.append(
        Paragraph(
            f"<b>Cliente:</b> "
            f"{escape(str(invoice.customer_name))}",
            styles["Normal"],
        )
    )

    elements.append(
        Paragraph(
            f"<b>Emissão:</b> {format_date(invoice.issue_date)}",
            styles["Normal"],
        )
    )

    elements.append(
        Paragraph(
            f"<b>Vencimento:</b> {format_date(invoice.due_date)}",
            styles["Normal"],
        )
    )

    elements.append(Spacer(1, 20))

    # Itens da fatura
    table_data = [
        ["Descrição", "Qtd.", "Valor unitário", "Total"]
    ]

    for item in invoice.items:
        table_data.append(
            [
                Paragraph(
                    escape(str(item.description)),
                    styles["Normal"],
                ),
                str(item.quantity),
                format_currency(item.unit_price),
                format_currency(item.total),
            ]
        )

    items_table = Table(
        table_data,
        colWidths=[8 * cm, 1.5 * cm, 3 * cm, 3 * cm],
        repeatRows=1,
    )

    items_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1F4E79"),
                ),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    elements.append(items_table)
    elements.append(Spacer(1, 20))

    # Total da fatura
    elements.append(
        Paragraph(
            f"<b>Total da fatura: "
            f"{format_currency(invoice.total)}</b>",
            styles["RightAligned"],
        )
    )

    # Rodapé
    elements.append(Spacer(1, 30))
    elements.append(
        Paragraph(
            "Documento gerado automaticamente pela plataforma.",
            styles["Normal"],
        )
    )

    document.build(elements)

    pdf_bytes = buffer.getvalue()
    buffer.close()

    return pdf_bytes


@router.get("/{invoice_id}/pdf")
def download_invoice_pdf(
    invoice_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Gera e retorna o PDF de uma fatura pertencente
    à empresa do usuário autenticado.
    """

    # Isolamento entre locatários:
    # consulta simultaneamente pelo ID da fatura
    # e pelo ID da empresa do usuário autenticado.
    statement = select(Invoice).where(
        Invoice.id == invoice_id,
        Invoice.company_id == current_user.company_id,
    )

    invoice = db.scalar(statement)

    if invoice is None:
        raise HTTPException(
            status_code=404,
            detail="Fatura não encontrada.",
        )

    pdf_content = generate_invoice_pdf(invoice)

    filename = f"fatura_{invoice.number}.pdf"

    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            ),
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )