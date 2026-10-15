# app/api/invoices.py

from io import BytesIO

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy.orm import Session

from app.databaseimport get_db
from app.modelsimport Invoice
from app.authimport get_current_user


router= APIRouter(prefix="/invoices", tags=["invoices"])


@router.get("/{invoice_id}/pdf")
def download_invoice_pdf(
    invoice_id: int,
    db: Session= Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Gera e retorna o PDF de uma fatura pertencente ao tenant
    do usuário autenticado.
    """

    invoice= (
        db.query(Invoice)
        .filter(
            Invoice.id== invoice_id,
            Invoice.tenant_id== current_user.tenant_id,
        )
        .first()
    )

    if invoiceis None:
        raise HTTPException(
            status_code=404,
            detail="Fatura não encontrada",
        )

    pdf_buffer= BytesIO()

    pdf= canvas.Canvas(pdf_buffer, pagesize=A4)
    width, height= A4

    pdf.setTitle(f"Fatura{invoice.number}")

    pdf.setFont("Helvetica-Bold",18)
    pdf.drawString(50, height- 60,"Relatório de Fatura")

    pdf.setFont("Helvetica",11)

    y= height- 100

    fields= [
        ("Número", invoice.number),
        ("Data de emissão", str(invoice.issue_date)),
        ("Cliente", invoice.customer_name),
        ("Status", invoice.status),
        ("Valor", f"R${invoice.total:.2f}"),
    ]

    for label, valuein fields:
        pdf.setFont("Helvetica-Bold",10)
        pdf.drawString(50, y,f"{label}:")

        pdf.setFont("Helvetica",10)
        pdf.drawString(170, y,str(value))

        y-= 25

    pdf.showPage()
    pdf.save()

    pdf_buffer.seek(0)

    filename= f"fatura-{invoice.number}.pdf"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition":f'attachment; filename="{filename}"'
        },
    )