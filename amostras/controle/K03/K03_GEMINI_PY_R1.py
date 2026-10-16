import io
import html
from typing import Optional
from datetime import date

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = FastAPI(title="SaaS Invoice API")
security = HTTPBearer()

# --- DTOs / Schemas ---

class UserContext(BaseModel):
    user_id: str
    tenant_id: str


class InvoiceItem(BaseModel):
    description: str
    quantity: int
    unit_price: float


class InvoiceData(BaseModel):
    invoice_id: str
    tenant_id: str
    issue_date: date
    customer_name: str
    items: list[InvoiceItem]


# --- Autenticação & Contexto de Locatário ---

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),) -> UserContext:
    """
    Decodifica e valida o JWT para extrair a identidade do usuário e o tenant_id.
    Em produção, deve validar assinatura, expiração (exp) e emissor (iss).
    """
    token = credentials.credentials
    # Mock de validação de token JWT:
    if not token or token == "invalid":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticação inválido ou expirado.",
        )

    # Exemplo de contexto extraído do payload do JWT validado
    return UserContext(user_id="usr_12345", tenant_id="tenant_company_a")


# --- Camada de Dados (Simulação) ---

def fetch_invoice_from_db(invoice_id: str) -> Optional[InvoiceData]:
    """Simula busca da fatura no banco de dados isolado/filtrado."""
    database = {
        "inv_9901": InvoiceData(
            invoice_id="inv_9901",
            tenant_id="tenant_company_a",
            issue_date=date(2026, 10, 1),
            customer_name="Cliente Exemplo LTDA",
            items=[
                InvoiceItem(description="Plano Enterprise - Mensal", quantity=1, unit_price=1500.00),
                InvoiceItem(description="Suporte Dedicado 24/7", quantity=1, unit_price=300.00),
            ],
        ),
        "inv_9902": InvoiceData(
            invoice_id="inv_9902",
            tenant_id="tenant_company_b",  # Outra empresa!
            issue_date=date(2026, 10, 5),
            customer_name="Outra Empresa S.A.",
            items=[
                InvoiceItem(description="Plano Basic - Mensal", quantity=1, unit_price=200.00),
            ],
        ),
    }
    return database.get(invoice_id)


# --- Serviço de Geração de PDF ---

def generate_invoice_pdf(invoice: InvoiceData) -> io.BytesIO:
    """
    Gera um arquivo PDF formatado na memória (sem gravar em disco)
    sanitizando entradas para evitar injeções.
    """
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
        textColor=colors.HexColor("#1A202C"),
    )

    story = []

    # Sanitização contra Injeção HTML/Script no PDF
    customer_safe = html.escape(invoice.customer_name)
    invoice_id_safe = html.escape(invoice.invoice_id)

    # Cabeçalho
    story.append(Paragraph(f"Fatura #{invoice_id_safe}", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Data de Emissão:</b> {invoice.issue_date.strftime('%d/%m/%Y')}", normal_style))
    story.append(Paragraph(f"<b>Cliente:</b> {customer_safe}", normal_style))
    story.append(Spacer(1, 20))

    # Tabela de Itens
    table_data = [["Descrição", "Qtd", "Preço Un.", "Total"]]
    total_amount = 0.0

    for item in invoice.items:
        item_total = item.quantity * item.unit_price
        total_amount += item_total

        desc_safe = html.escape(item.description)
        table_data.append([
            Paragraph(desc_safe, normal_style),
            str(item.quantity),
            f"R$ {item.unit_price:,.2f}",
            f"R$ {item_total:,.2f}",
        ])

    table_data.append(["", "", "Total Fatura:", f"R$ {total_amount:,.2f}"])

    table = Table(table_data, colWidths=[280, 50, 100, 100])
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#2D3748")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -2), 0.5, colors.HexColor("#CBD5E0")),
            ("LINEABOVE", (2, -1), (3, -1), 1, colors.HexColor("#2D3748")),
            ("FONTNAME", (2, -1), (3, -1), "Helvetica-Bold"),
        ])
    )

    story.append(table)
    doc.build(story)

    buffer.seek(0)
    return buffer


# --- Endpoint de API ---

@app.get(
    "/api/v1/invoices/{invoice_id}/download",
    response_class=StreamingResponse,
    summary="Download do relatório de fatura em PDF",)
def download_invoice_pdf(
    invoice_id: str,
    current_user: UserContext = Depends(get_current_user),):
    # 1. Busca do recurso
    invoice = fetch_invoice_from_db(invoice_id)
    if not invoice:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fatura não encontrada.",
        )

    # 2. Defesa contra OWASP A01: Broken Access Control (IDOR)
    # Valida rigorosamente se a fatura pertence ao locatário autenticado
    if invoice.tenant_id != current_user.tenant_id:
        # Retorna 404 para evitar inferência de existência do recurso (Enumeration Prevention)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fatura não encontrada.",
        )

    # 3. Geração do PDF em memória (OWASP A04)
    pdf_buffer = generate_invoice_pdf(invoice)

    # 4. Headers de segurança para download de arquivo
    filename = f"fatura_{invoice.invoice_id}.pdf"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
    }

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers=headers,
    )