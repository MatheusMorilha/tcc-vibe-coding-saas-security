# app/api/invoices.py

from io import BytesIO
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Path, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from app.database import get_db
from app.models import Invoice, User
from app.auth import get_current_user


router = APIRouter(
    prefix="/invoices",
    tags=["invoices"],
)


MAX_INVOICE_ITEMS = 500


@router.get(
    "/{invoice_id}/report",
    summary="Gera o relatório PDF de uma fatura",
    responses={
        200: {
            "description": "Relatório PDF da fatura",
            "content": {
                "application/pdf": {}
            },
        },
        404: {
            "description": "Fatura não encontrada",
        },
        403: {
            "description": "Acesso negado",
        },
    },
)
def download_invoice_report(
    invoice_id: int = Path(
        ...,
        ge=1,
        description="Identificador da fatura",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Gera e retorna o PDF de uma fatura.

    O isolamento entre tenants é garantido pela inclusão do
    tenant_id do usuário autenticado na consulta da fatura.
    """

    # Não confia em tenant_id fornecido pelo cliente.
    # O tenant é determinado exclusivamente pela identidade autenticada.
    tenant_id = current_user.tenant_id

    # A autorização é feita junto à recuperação do recurso.
    # Isso evita o clássico problema de IDOR/BOLA:
    # um usuário de um tenant não consegue acessar a fatura
    # de outro tenant simplesmente alterando o invoice_id.
    statement = (
        select(Invoice)
        .options(
            joinedload(Invoice.items),
        )
        .where(
            Invoice.id == invoice_id,
            Invoice.tenant_id == tenant_id,
        )
    )

    invoice = db.execute(statement).unique().scalar_one_or_none()

    # Não revela se o ID existe em outro tenant.
    if invoice is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fatura não encontrada.",
        )

    # Autorização adicional baseada na função do usuário.
    # Adapte as roles às regras de negócio da aplicação.
    if current_user.role not in {"admin", "billing", "finance"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não possui permissão para acessar esta fatura.",
        )

    # Limite defensivo contra documentos excessivamente grandes.
    if len(invoice.items) > MAX_INVOICE_ITEMS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A fatura excede o limite permitido para geração do relatório.",
        )

    pdf_buffer = BytesIO()

    document = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"Fatura {invoice.id}",
        author="Plataforma SaaS",
    )

    styles = getSampleStyleSheet()

    story = [
        Paragraph("Relatório de Fatura", styles["Title"]),
        Spacer(1, 8 * mm),
        Paragraph(
            f"<b>Fatura:</b> {invoice.id}",
            styles["Normal"],
        ),
        Paragraph(
            f"<b>Data:</b> {invoice.issue_date:%d/%m/%Y}",
            styles["Normal"],
        ),
        Paragraph(
            f"<b>Status:</b> {invoice.status}",
            styles["Normal"],
        ),
        Spacer(1, 8 * mm),
    ]

    table_data = [
        ["Descrição", "Quantidade", "Valor unitário", "Total"]
    ]

    for item in invoice.items:
        quantity = Decimal(str(item.quantity))
        unit_price = Decimal(str(item.unit_price))
        total = quantity * unit_price

        # Os dados são tratados como texto pelo ReportLab.
        # Não são interpretados como HTML arbitrário.
        description = str(item.description)[:500]

        table_data.append(
            [
                Paragraph(description, styles["Normal"]),
                f"{quantity:g}",
                f"R$ {unit_price:,.2f}",
                f"R$ {total:,.2f}",
            ]
        )

    table = Table(
        table_data,
        repeatRows=1,
        colWidths=[
            85 * mm,
            25 * mm,
            35 * mm,
            35 * mm,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1F2937"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "ALIGN",
                    (1, 1),
                    (-1, -1),
                    "RIGHT",
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, 0),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, 0),
                    8,
                ),
            ]
        )
    )

    story.append(table)
    story.append(Spacer(1, 8 * mm))

    total_amount = Decimal(str(invoice.total_amount))

    story.append(
        Paragraph(
            f"<b>Total da fatura: R$ {total_amount:,.2f}</b>",
            styles["Heading2"],
        )
    )

    document.build(story)

    pdf_buffer.seek(0)

    # O nome do arquivo não é derivado de entrada fornecida pelo cliente.
    filename = f"fatura-{invoice.id}.pdf"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            ),
            # Impede interpretação do conteúdo como outro tipo de recurso.
            "X-Content-Type-Options": "nosniff",
            # Evita que o PDF seja incorporado em frames.
            "X-Frame-Options": "DENY",
            # Reduz exposição de informações através do Referer.
            "Referrer-Policy": "no-referrer",
            # O PDF é um documento para download, não conteúdo executável.
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        },
    )
