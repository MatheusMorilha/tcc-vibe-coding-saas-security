# main.py

from io import BytesIO
from datetime import datetime
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session, joinedload
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
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

# Substitua estes imports pelos módulos existentes no seu projeto.
from app.database import get_db
from app.models import Invoice, InvoiceItem
from app.auth import get_current_user


router = APIRouter(prefix="/invoices", tags=["Invoices"])


@router.get("/{invoice_id}/pdf")
def download_invoice_pdf(
    invoice_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Gera um PDF da fatura e o retorna para download.

    A autorização é baseada no tenant do usuário autenticado.
    """

    # Busca a fatura dentro do tenant do usuário autenticado.
    invoice = (
        db.query(Invoice)
        .options(joinedload(Invoice.items))
        .filter(
            Invoice.id == invoice_id,
            Invoice.tenant_id == current_user.tenant_id,
        )
        .first()
    )

    # Não revela se a fatura existe em outro tenant.
    if invoice is None:
        raise HTTPException(
            status_code=404,
            detail="Fatura não encontrada.",
        )

    # Cria o PDF em memória, sem armazenar arquivos no servidor.
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"Fatura {invoice.id}",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "InvoiceTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#1F3A5F"),
        spaceAfter=20,
    )

    story = []

    story.append(Paragraph("RELATÓRIO DE FATURA", title_style))
    story.append(Paragraph(
        f"<b>Número:</b> {escape(str(invoice.id))}",
        styles["Normal"],
    ))
    story.append(Paragraph(
        f"<b>Data de emissão:</b> "
        f"{escape(str(invoice.issue_date))}",
        styles["Normal"],
    ))
    story.append(Paragraph(
        f"<b>Status:</b> {escape(str(invoice.status))}",
        styles["Normal"],
    ))
    story.append(Spacer(1, 16))

    # Os campos abaixo devem corresponder ao modelo InvoiceItem.
    table_data = [
        ["Descrição", "Quantidade", "Preço unitário", "Subtotal"]
    ]

    total = 0.0

    for item in invoice.items:
        quantity = float(item.quantity)
        unit_price = float(item.unit_price)
        subtotal = quantity * unit_price
        total += subtotal

        table_data.append([
            Paragraph(escape(str(item.description)), styles["BodyText"]),
            f"{quantity:g}",
            f"R$ {unit_price:,.2f}",
            f"R$ {subtotal:,.2f}",
        ])

    table = Table(
        table_data,
        colWidths=[8 * cm, 2 * cm, 3 * cm, 3 * cm],
        repeatRows=1,
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
    ]))

    story.append(table)
    story.append(Spacer(1, 20))

    story.append(Paragraph(
        f"<b>Total dos itens: R$ {total:,.2f}</b>",
        styles["Heading2"],
    ))

    document.build(story)

    buffer.seek(0)

    filename = f"fatura_{invoice.id}.pdf"

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            ),
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )