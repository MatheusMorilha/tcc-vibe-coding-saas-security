# app.py

from io import BytesIO

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import Column, Integer, String, Numeric, ForeignKey
from sqlalchemy.orm import Session, declarative_base, relationship
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

Base= declarative_base()
app= FastAPI()


# -------------------------------------------------------------------
# Modelos
# -------------------------------------------------------------------

class Invoice(Base):
    __tablename__= "invoices"

    id = Column(Integer, primary_key=True)
    tenant_id= Column(Integer, nullable=False, index=True)
    customer_name= Column(String, nullable=False)
    total= Column(Numeric(12,2), nullable=False)

    items= relationship("InvoiceItem", back_populates="invoice")


class InvoiceItem(Base):
    __tablename__= "invoice_items"

    id = Column(Integer, primary_key=True)
    invoice_id= Column(
        Integer,
        ForeignKey("invoices.id"),
        nullable=False,
    )
    description= Column(String, nullable=False)
    quantity= Column(Integer, nullable=False)
    unit_price= Column(Numeric(12,2), nullable=False)

    invoice= relationship("Invoice", back_populates="items")


# -------------------------------------------------------------------
# Dependências de autenticação/tenant
# -------------------------------------------------------------------

def get_db():
    """
    Substitua pela sessão SQLAlchemy utilizada pela aplicação.
    """
    db= Session()
    try:
        yield db
    finally:
        db.close()


def get_current_tenant_id()-> int:
    """
    Na aplicação real, obtenha o tenant_id a partir do usuário
    autenticado/token de sessão.

    Nunca aceite tenant_id enviado pelo cliente como mecanismo
    de autorização.
    """
    # Exemplo apenas para demonstrar a integração.
    return 123


# -------------------------------------------------------------------
# Geração do PDF
# -------------------------------------------------------------------

def generate_invoice_pdf(invoice: Invoice)-> BytesIO:
    buffer= BytesIO()

    pdf= canvas.Canvas(buffer, pagesize=A4)
    width, height= A4

    y= height- 50

    pdf.setFont("Helvetica-Bold",18)
    pdf.drawString(50, y,f"Fatura #{invoice.id}")

    y-= 35

    pdf.setFont("Helvetica",11)
    pdf.drawString(50, y,f"Cliente:{invoice.customer_name}")

    y-= 35

    pdf.setFont("Helvetica-Bold",11)
    pdf.drawString(50, y,"Descrição")
    pdf.drawString(300, y,"Quantidade")
    pdf.drawString(400, y,"Preço unitário")
    pdf.drawString(500, y,"Subtotal")

    y-= 20
    pdf.setFont("Helvetica",10)

    for itemin invoice.items:
        subtotal= item.quantity* item.unit_price

        pdf.drawString(50, y, item.description[:35])
        pdf.drawString(300, y,str(item.quantity))
        pdf.drawString(400, y,f"R${item.unit_price:.2f}")
        pdf.drawString(500, y,f"R${subtotal:.2f}")

        y-= 20

        # Evita escrever fora da página.
        if y< 50:
            pdf.showPage()
            y= height- 50
            pdf.setFont("Helvetica",10)

    y-= 15

    pdf.setFont("Helvetica-Bold",12)
    pdf.drawString(400, y,f"Total: R${invoice.total:.2f}")

    pdf.save()

    buffer.seek(0)
    return buffer


# -------------------------------------------------------------------
# Endpoint
# -------------------------------------------------------------------

@app.get(
    "/api/invoices/{invoice_id}/report",
    response_class=StreamingResponse,
)
def download_invoice_report(
    invoice_id: int,
    db: Session= Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """
    Gera e retorna o relatório PDF da fatura.

    O tenant_id é aplicado diretamente na consulta para garantir
    isolamento entre empresas.
    """

    invoice= (
        db.query(Invoice)
        .filter(
            Invoice.id== invoice_id,
            Invoice.tenant_id== tenant_id,
        )
        .first()
    )

    # Não revelar se a fatura existe em outro tenant.
    if invoiceis None:
        raise HTTPException(
            status_code=404,
            detail="Fatura não encontrada",
        )

    pdf= generate_invoice_pdf(invoice)

    filename= f"fatura-{invoice.id}.pdf"

    return StreamingResponse(
        pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            )
        },
    )