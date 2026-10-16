from decimal import Decimal
from io import BytesIO
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Path, status
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import ForeignKey, Numeric, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship

DATABASE_URL = "sqlite:///./app.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(primary_key=True)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(320))


class Invoice(Base):
    __tablename__ = "invoices"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    number: Mapped[str] = mapped_column(String(50))
    customer_name: Mapped[str] = mapped_column(String(255))
    total: Mapped[Decimal] = mapped_column(Numeric(12, 2))

    items: Mapped[list["InvoiceItem"]] = relationship(
        back_populates="invoice",
        cascade="all, delete-orphan",
    )


class InvoiceItem(Base):
    __tablename__ = "invoice_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    invoice_id: Mapped[int] = mapped_column(
        ForeignKey("invoices.id"),
        index=True,
    )
    description: Mapped[str] = mapped_column(String(500))
    quantity: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    unit_price: Mapped[Decimal] = mapped_column(Numeric(12, 2))

    invoice: Mapped[Invoice] = relationship(back_populates="items")


Base.metadata.create_all(engine)

app = FastAPI(title="SaaS API")


def get_db():
    with Session(engine) as session:
        yield session


# Em uma aplicação real, esta dependência deve validar o token
# (por exemplo, JWT/OIDC) e retornar o usuário autenticado.
def get_current_user() -> User:
    # Exemplo apenas para demonstrar a interface da dependência.
    # Não use um usuário fixo em produção.
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Autenticação necessária",
    )


CurrentUser = Annotated[User, Depends(get_current_user)]
Database = Annotated[Session, Depends(get_db)]


def get_invoice_for_tenant(
    db: Session,
    invoice_id: int,
    tenant_id: int,
) -> Invoice:
    """
    Busca a fatura sempre limitada ao tenant autenticado.

    O tenant_id faz parte do predicado da consulta, evitando que
    conhecer o ID de uma fatura de outro cliente permita acessá-la.
    """
    invoice = db.scalar(
        select(Invoice)
        .where(
            Invoice.id == invoice_id,
            Invoice.tenant_id == tenant_id,
        )
    )

    if invoice is None:
        # Não revela se a fatura existe em outro tenant.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fatura não encontrada",
        )

    return invoice


def build_invoice_pdf(invoice: Invoice) -> BytesIO:
    """
    Gera o PDF exclusivamente a partir de dados já autorizados.
    """

    output = BytesIO()

    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title=f"Fatura {invoice.number}",
        author="SaaS",
    )

    styles = getSampleStyleSheet()

    elements = [
        Paragraph("RELATÓRIO DE FATURA", styles["Title"]),
        Spacer(1, 8 * mm),
        Paragraph(
            f"<b>Fatura:</b> {invoice.number}",
            styles["Normal"],
        ),
        Paragraph(
            f"<b>Cliente:</b> {invoice.customer_name}",
            styles["Normal"],
        ),
        Spacer(1, 8 * mm),
    ]

    table_data = [
        ["Descrição", "Quantidade", "Valor unitário", "Subtotal"]
    ]

    calculated_total = Decimal("0.00")

    for item in invoice.items:
        subtotal = item.quantity * item.unit_price
        calculated_total += subtotal

        table_data.append(
            [
                Paragraph(item.description, styles["Normal"]),
                f"{item.quantity:.2f}",
                f"R$ {item.unit_price:.2f}",
                f"R$ {subtotal:.2f}",
            ]
        )

    table_data.append(
        [
            "",
            "",
            "Total",
            f"R$ {calculated_total:.2f}",
        ]
    )

    table = Table(
        table_data,
        colWidths=[
            85 * mm,
            25 * mm,
            35 * mm,
            35 * mm,
        ],
        repeatRows=1,
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
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (-2, -1), (-1, -1), "Helvetica-Bold"),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#E5E7EB")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    elements.append(table)
    document.build(elements)

    output.seek(0)
    return output


@app.get(
    "/api/v1/invoices/{invoice_id}/report",
    response_class=StreamingResponse,
)
def download_invoice_report(
    invoice_id: Annotated[int, Path(gt=0)],
    current_user: CurrentUser,
    db: Database,
):
    """
    Gera e retorna o relatório PDF da fatura.

    A autorização é feita antes de qualquer dado da fatura ser
    utilizado para gerar o documento.
    """

    invoice = get_invoice_for_tenant(
        db=db,
        invoice_id=invoice_id,
        tenant_id=current_user.tenant_id,
    )

    # Autorização adicional pode ser aplicada aqui caso o sistema
    # tenha papéis/permissões específicas para consultar faturas.
    #
    # Exemplo:
    #
    # if not current_user.can("invoice:read"):
    #     raise HTTPException(status_code=403)

    pdf = build_invoice_pdf(invoice)

    filename = f"fatura-{invoice.id}.pdf"

    return StreamingResponse(
        pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'",
        },
    )
