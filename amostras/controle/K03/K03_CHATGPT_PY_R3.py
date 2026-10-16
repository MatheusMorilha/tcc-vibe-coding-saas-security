from __future__ import annotations

from decimal import Decimal
from io import BytesIO
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Path, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import ForeignKey, Numeric, String, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


app = FastAPI(
    title="SaaS API",
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# Banco de dados
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class Invoice(Base):
    __tablename__ = "invoices"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"),
        nullable=False,
        index=True,
    )
    customer_name: Mapped[str] = mapped_column(String(200), nullable=False)
    number: Mapped[str] = mapped_column(String(50), nullable=False)
    total: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)


class InvoiceItem(Base):
    __tablename__ = "invoice_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    invoice_id: Mapped[int] = mapped_column(
        ForeignKey("invoices.id"),
        nullable=False,
        index=True,
    )
    description: Mapped[str] = mapped_column(String(500), nullable=False)
    quantity: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    unit_price: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)


# ---------------------------------------------------------------------------
# Autenticação/autorização
# ---------------------------------------------------------------------------

class CurrentUser(BaseModel):
    """
    Representa o usuário obtido a partir do mecanismo de autenticação
    da aplicação.

    Em produção, este objeto deve ser criado por um middleware/dependency
    que valide, por exemplo, um JWT ou sessão server-side.
    """

    model_config = ConfigDict(frozen=True)

    user_id: int
    tenant_id: int
    is_active: bool


def get_current_user() -> CurrentUser:
    """
    Substitua esta implementação pelo mecanismo de autenticação real.

    IMPORTANTE:
    Não aceite tenant_id diretamente de query parameter, header ou body
    para decidir a empresa do usuário.
    """

    # Exemplo apenas para demonstrar a interface.
    # Em produção, deve ocorrer validação criptográfica do token/sessão.
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não autenticado",
        headers={"WWW-Authenticate": "Bearer"},
    )


CurrentUserDependency = Annotated[
    CurrentUser,
    Depends(get_current_user),
]


# ---------------------------------------------------------------------------
# Banco
# ---------------------------------------------------------------------------

def get_db() -> Session:
    """
    Substitua pelo SessionLocal/engine configurado na aplicação.

    Exemplo:

        with SessionLocal() as session:
            yield session
    """
    raise NotImplementedError("Configure a conexão com o banco de dados")


# ---------------------------------------------------------------------------
# Schemas internos
# ---------------------------------------------------------------------------

class InvoiceReportData(BaseModel):
    invoice_number: str
    customer_name: str
    total: Decimal
    items: list[tuple[str, Decimal, Decimal]]


# ---------------------------------------------------------------------------
# Geração do PDF
# ---------------------------------------------------------------------------

def build_invoice_pdf(invoice: Invoice, items: list[InvoiceItem]) -> BytesIO:
    """
    Gera o PDF inteiramente em memória.

    Os valores do banco são tratados como texto simples pelo ReportLab.
    Não utilizamos HTML fornecido pelo usuário como template, evitando
    uma superfície desnecessária para injeção durante a renderização.
    """

    output = BytesIO()

    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Fatura {invoice.number}",
        author="SaaS",
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    normal_style = styles["BodyText"]

    elements = []

    elements.append(
        Paragraph(
            "Relatório de Fatura",
            title_style,
        )
    )

    elements.append(Spacer(1, 8 * mm))

    elements.append(
        Paragraph(
            f"<b>Fatura:</b> {escape_reportlab(invoice.number)}",
            normal_style,
        )
    )

    elements.append(
        Paragraph(
            f"<b>Cliente:</b> {escape_reportlab(invoice.customer_name)}",
            normal_style,
        )
    )

    elements.append(Spacer(1, 8 * mm))

    rows = [
        [
            Paragraph("<b>Descrição</b>", normal_style),
            Paragraph("<b>Quantidade</b>", normal_style),
            Paragraph("<b>Preço unitário</b>", normal_style),
            Paragraph("<b>Total</b>", normal_style),
        ]
    ]

    for item in items:
        item_total = item.quantity * item.unit_price

        rows.append(
            [
                Paragraph(
                    escape_reportlab(item.description),
                    normal_style,
                ),
                Paragraph(
                    escape_reportlab(format_decimal(item.quantity)),
                    normal_style,
                ),
                Paragraph(
                    escape_reportlab(format_currency(item.unit_price)),
                    normal_style,
                ),
                Paragraph(
                    escape_reportlab(format_currency(item_total)),
                    normal_style,
                ),
            ]
        )

    rows.append(
        [
            "",
            "",
            Paragraph("<b>Total da fatura</b>", normal_style),
            Paragraph(
                f"<b>{escape_reportlab(format_currency(invoice.total))}</b>",
                normal_style,
            ),
        ]
    )

    table = Table(
        rows,
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
                    colors.HexColor("#eeeeee"),
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#cccccc"),
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
                    "BACKGROUND",
                    (0, -1),
                    (-1, -1),
                    colors.HexColor("#f5f5f5"),
                ),
            ]
        )
    )

    elements.append(table)

    document.build(elements)

    output.seek(0)
    return output


def escape_reportlab(value: object) -> str:
    """
    Escapa caracteres que possuem significado em markup do ReportLab.

    Isso é importante porque Paragraph interpreta uma pequena linguagem
    de markup semelhante a HTML.
    """
    text = str(value)

    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def format_decimal(value: Decimal) -> str:
    return f"{value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def format_currency(value: Decimal) -> str:
    return f"R$ {format_decimal(value)}"


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@app.get(
    "/api/invoices/{invoice_id}/report.pdf",
    response_class=StreamingResponse,
    responses={
        200: {
            "description": "Relatório PDF da fatura",
            "content": {
                "application/pdf": {}
            },
        },
        401: {
            "description": "Usuário não autenticado",
        },
        403: {
            "description": "Usuário sem permissão",
        },
        404: {
            "description": "Fatura não encontrada",
        },
    },
)
def download_invoice_report(
    invoice_id: int = Path(
        ...,
        ge=1,
        description="ID interno da fatura",
    ),
    current_user: CurrentUserDependency = None,
    db: Session = Depends(get_db),
):
    """
    Retorna o relatório PDF de uma fatura.

    O ponto crítico de segurança é o filtro:

        Invoice.tenant_id == current_user.tenant_id

    Assim, mesmo que um usuário descubra o ID de uma fatura pertencente
    a outra empresa, ela não será retornada.
    """

    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuário inativo",
        )

    # ------------------------------------------------------------------
    # Controle de acesso por objeto + tenant isolation
    # ------------------------------------------------------------------
    #
    # NÃO fazer:
    #
    # invoice = db.get(Invoice, invoice_id)
    #
    # pois isso permite que a existência de um ID seja suficiente para
    # acessar uma fatura de outro tenant.
    #
    # O tenant autenticado precisa fazer parte da consulta.
    # ------------------------------------------------------------------

    invoice_statement = (
        select(Invoice)
        .where(
            Invoice.id == invoice_id,
            Invoice.tenant_id == current_user.tenant_id,
        )
    )

    invoice = db.scalar(invoice_statement)

    if invoice is None:
        # Não diferenciamos "não existe" de "existe em outro tenant".
        # Isso reduz exposição de informações entre tenants.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fatura não encontrada",
        )

    # ------------------------------------------------------------------
    # Os itens também são obtidos indiretamente através da fatura já
    # validada para o tenant.
    # ------------------------------------------------------------------

    items_statement = (
        select(InvoiceItem)
        .where(InvoiceItem.invoice_id == invoice.id)
        .order_by(InvoiceItem.id)
    )

    items = list(db.scalars(items_statement))

    try:
        pdf = build_invoice_pdf(invoice, items)
    except Exception:
        # Não retornar detalhes internos da exceção ao cliente.
        # O erro deve ser registrado em um sistema de observabilidade
        # seguro, sem incluir dados sensíveis no log.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível gerar o relatório",
        )

    filename = make_safe_filename(invoice.number)

    return StreamingResponse(
        pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            ),
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


def make_safe_filename(invoice_number: str) -> str:
    """
    Impede que dados da fatura controlem o nome do arquivo de maneira
    arbitrária.

    Mantemos apenas caracteres alfanuméricos, hífen e underscore.
    """

    safe = "".join(
        char
        for char in invoice_number
        if char.isalnum() or char in ("-", "_")
    )

    if not safe:
        safe = "fatura"

    return f"fatura-{safe}.pdf"
