from io import BytesIO
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import create_engine, Column, Integer, String, Numeric, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


DATABASE_URL= "sqlite:///./saas.db"

engine= create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread":False},
)

SessionLocal= sessionmaker(bind=engine)
Base= declarative_base()

app= FastAPI(title="SaaS Invoice API")


class Invoice(Base):
    __tablename__= "invoices"

    id = Column(Integer, primary_key=True)
    tenant_id= Column(Integer, nullable=False, index=True)
    customer_name= Column(String, nullable=False)
    description= Column(String, nullable=False)
    amount= Column(Numeric(12,2), nullable=False)
    status= Column(String, nullable=False)


Base.metadata.create_all(bind=engine)


def get_db():
    db= SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_tenant_id()-> int:
    """
    Em uma aplicação real, o tenant_id deve ser obtido
    do token/sessão autenticado, nunca de um parâmetro enviado
    pelo cliente.
    """
    # Exemplo simplificado.
    return 1


@app.get("/invoices/{invoice_id}/report.pdf")
def generate_invoice_report(
    invoice_id: int,
    db: Session= Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    # O tenant_id faz parte da consulta para impedir que um
    # usuário acesse uma fatura pertencente a outro tenant.
    invoice= (
        db.query(Invoice)
        .filter(
            Invoice.id== invoice_id,
            Invoice.tenant_id== tenant_id,
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

    y= height- 60

    pdf.setTitle(f"Fatura{invoice.id}")

    pdf.setFont("Helvetica-Bold",18)
    pdf.drawString(50, y,"Relatório de Fatura")

    y-= 40

    pdf.setFont("Helvetica",11)
    pdf.drawString(50, y,f"Fatura: #{invoice.id}")
    y-= 20

    pdf.drawString(50, y,f"Cliente:{invoice.customer_name}")
    y-= 20

    pdf.drawString(50, y,f"Descrição:{invoice.description}")
    y-= 20

    pdf.drawString(50, y,f"Valor: R${invoice.amount:.2f}")
    y-= 20

    pdf.drawString(50, y,f"Status:{invoice.status}")
    y-= 20

    pdf.drawString(
        50,
        y,
        f"Gerado em:{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
    )

    pdf.showPage()
    pdf.save()

    pdf_buffer.seek(0)

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="fatura-{invoice.id}.pdf"'
            )
        },
    )