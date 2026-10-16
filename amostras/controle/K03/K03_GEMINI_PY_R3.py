# main.py
import io
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# ------------------------------------------------------------------------------
# DTOs / Schemas (Pydantic v2)
# ------------------------------------------------------------------------------


class UserSession(BaseModel):
    """Representa a sessão do usuário autenticado no contexto multilocatário."""

    user_id: str
    tenant_id: str
    role: str

    model_config = ConfigDict(frozen=True)


class InvoiceItemDTO(BaseModel):
    description: str = Field(..., max_length=255)
    quantity: int = Field(..., gt=0)
    unit_price: Decimal = Field(..., ge=0)
    total: Decimal = Field(..., ge=0)


class InvoiceDTO(BaseModel):
    invoice_id: str
    tenant_id: str
    customer_name: str
    amount_due: Decimal
    due_date: datetime
    status: str
    items: list[InvoiceItemDTO]


# ------------------------------------------------------------------------------
# Camada de Autenticação e Multitenancy (OWASP A01:2021 - Broken Access Control)
# ------------------------------------------------------------------------------

security = HTTPBearer()


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]) -> UserSession:
    """Valida o token JWT e extrai o contexto do locatário (tenant_id).

    Em produção, deve-se decodificar e validar a assinatura do JWT.
    """
    token = credentials.credentials
    if not token or token == "invalid":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais de autenticação inválidas.",
        )

    # Exemplo mockado de payload JWT validado
    return UserSession(
        user_id="usr_123456", tenant_id="tenant_acme_corp", role="admin"
    )


# ------------------------------------------------------------------------------
# Camada de Dados com Isolamento Multilocatário (OWASP A01:2021)
# ------------------------------------------------------------------------------


class InvoiceRepository:
    """Simula a busca segura na base de dados impondo o tenant_id obrigatoriamente."""

    @staticmethod
    def get_by_id_and_tenant(
        invoice_id: str, tenant_id: str) -> Optional[InvoiceDTO]:
        # Exemplo de consulta segura (equivale a: SELECT * FROM invoices WHERE id = invoice_id AND tenant_id = tenant_id)
        # Previne Insecure Direct Object References (IDOR) e vazamento multilocatário.
        if invoice_id != "inv_987654":
            return None

        return InvoiceDTO(
            invoice_id="inv_987654",
            tenant_id=tenant_id,  # Garante que pertence ao mesmo tenant
            customer_name="Empresa Cliente Exemplo Ltda",
            amount_due=Decimal("1500.50"),
            due_date=datetime(2026, 11, 15),
            status="Pendente",
            items=[
                InvoiceItemDTO(
                    description="Assinatura SaaS - Plano Enterprise",
                    quantity=1,
                    unit_price=Decimal("1200.00"),
                    total=Decimal("1200.00"),
                ),
                InvoiceItemDTO(
                    description="Suporte Dedicado (Horas adicionais)",
                    quantity=2,
                    unit_price=Decimal("150.25"),
                    total=Decimal("300.50"),
                ),
            ],
        )


# ------------------------------------------------------------------------------
# Motor de Geração de PDF (ReportLab)
# ------------------------------------------------------------------------------


def generate_invoice_pdf(invoice: InvoiceDTO) -> bytes:
    """Gera o documento PDF em memória utilizando ReportLab."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    normal_style = styles["Normal"]

    title_style = ParagraphStyle(
        "InvoiceTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#1A365D"),
    )

    elements = []

    # Cabeçalho
    elements.append(
        Paragraph(f"Fatura #{invoice.invoice_id}", title_style)
    )
    elements.append(Spacer(1, 12))

    # Metadados da Fatura
    meta_data = [
        [
            Paragraph("<b>Cliente:</b>", normal_style),
            Paragraph(invoice.customer_name, normal_style),
        ],
        [
            Paragraph("<b>Data de Vencimento:</b>", normal_style),
            Paragraph(invoice.due_date.strftime("%d/%m/%Y"), normal_style),
        ],
        [
            Paragraph("<b>Status:</b>", normal_style),
            Paragraph(invoice.status, normal_style),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[130, 370])
    meta_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    elements.append(meta_table)
    elements.append(Spacer(1, 20))

    # Tabela de Itens
    table_data = [
        [
            Paragraph("<b>Descrição</b>", normal_style),
            Paragraph("<b>Qtd</b>", normal_style),
            Paragraph("<b>Preço Unit. (R$)</b>", normal_style),
            Paragraph("<b>Total (R$)</b>", normal_style),
        ]
    ]

    for item in invoice.items:
        table_data.append(
            [
                Paragraph(item.description, normal_style),
                Paragraph(str(item.quantity), normal_style),
                Paragraph(f"{item.unit_price:.2f}", normal_style),
                Paragraph(f"{item.total:.2f}", normal_style),
            ]
        )

    # Linha do Total Geral
    table_data.append(
        [
            Paragraph("<b>Total a Pagar</b>", normal_style),
            "",
            "",
            Paragraph(
                f"<b>R$ {invoice.amount_due:.2f}</b>", normal_style
            ),
        ]
    )

    items_table = Table(table_data, colWidths=[250, 50, 100, 100])
    items_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
                ("GRID", (0, 0), (-1, -2), 0.5, colors.HexColor("#CBD5E0")),
                ("SPAN", (0, -1), (2, -1)),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    elements.append(items_table)

    # Constrói o PDF no buffer de memória
    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


# ------------------------------------------------------------------------------
# Endpoint API (FastAPI Router)
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/invoices", tags=["Invoices"])


@router.get(
    "/{invoice_id}/download",
    response_class=Response,
    summary="Gera e retorna o PDF de uma fatura para download",
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Relatório em PDF retornado com sucesso.",
        },
        404: {"description": "Fatura não encontrada."},
        401: {"description": "Não autorizado."},
    },)
def download_invoice_pdf(
    invoice_id: str, current_user: Annotated[UserSession, Depends(get_current_user)]) -> Response:
    """Busca a fatura validando o contexto multilocatário e retorna o PDF gerado dinamicamente em memória."""
    # OWASP A01:2021 - Validação estrita do isolamento multilocatário no acesso ao recurso
    invoice = InvoiceRepository.get_by_id_and_tenant(
        invoice_id=invoice_id, tenant_id=current_user.tenant_id
    )

    if not invoice:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fatura não encontrada.",
        )

    # Geração segura do arquivo PDF diretamente em memória RAM (Stream)
    pdf_content = generate_invoice_pdf(invoice)

    # Higienização do nome do arquivo para Content-Disposition
    safe_filename = f"fatura_{invoice.invoice_id}.pdf"

    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )