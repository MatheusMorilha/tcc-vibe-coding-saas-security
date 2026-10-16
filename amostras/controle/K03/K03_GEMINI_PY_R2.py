import io
from typing import Annotated, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = FastAPI(title="SaaS Invoice API", version="1.0.0")
security = HTTPBearer()

# ------------------------------------------------------------------------------
# Modelos e Segurança
# ------------------------------------------------------------------------------

class UserContext(BaseModel):
    user_id: str
    tenant_id: str

def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]) -> UserContext:
    """
    Decodifica e valida o JWT para extrair a identidade do usuário e o Tenant ID.
    (Em produção, utilize validação de assinatura e verificação de revogação).
    """
    token = credentials.credentials
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticação ausente ou inválido.",
        )

    # Exemplo mockado de payload decodificado:
    # A garantia de multitenancy exige que o tenant_id venha do token assinado.
    return UserContext(user_id="usr_12345", tenant_id="tenant_abc")


# ------------------------------------------------------------------------------
# Camada de Dados (Simulação da Consulta ao Banco de Dados)
# ------------------------------------------------------------------------------

def get_invoice_by_id(invoice_id: str, tenant_id: str) -> Dict[str, Any] | None:
    """
    Simula a busca no banco de dados.
    A consulta SEMPRE filtra explicitamente pelo tenant_id para prevenir IDOR / Broken Access Control.
    """
    database_mock = {
        "inv_9988": {
            "invoice_id": "inv_9988",
            "tenant_id": "tenant_abc",
            "customer_name": "Empresa Cliente Ltda",
            "amount": 1450.00,
            "status": "Pago",
            "due_date": "2026-10-15",
            "items": [
                {"description": "Plano Pro SaaS - Mensal", "value": 1200.00},
                {"description": "Usuários Adicionais (5x)", "value": 250.00},
            ],
        }
    }

    invoice = database_mock.get(invoice_id)

    # Validação estrita de isolamento de tenant
    if not invoice or invoice["tenant_id"] != tenant_id:
        return None

    return invoice


# ------------------------------------------------------------------------------
# Gerador de PDF em Memória (ReportLab)
# ------------------------------------------------------------------------------

def generate_invoice_pdf(invoice_data: Dict[str, Any]) -> io.BytesIO:
    """
    Gera o PDF da fatura utilizando um fluxo em memória (BytesIO),
    garantindo performance e evitando persistência temporária no sistema de arquivos.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=12
    )

    story = []

    # Cabeçalho do Relatório
    story.append(Paragraph(f"Fatura #{invoice_data['invoice_id']}", title_style))
    story.append(Paragraph(f"<b>Cliente:</b> {invoice_data['customer_name']}", styles['Normal']))
    story.append(Paragraph(f"<b>Vencimento:</b> {invoice_data['due_date']}", styles['Normal']))
    story.append(Paragraph(f"<b>Status:</b> {invoice_data['status']}", styles['Normal']))
    story.append(Spacer(1, 16))

    # Tabela de Itens
    table_data = [["Descrição", "Valor (R$)"]]
    for item in invoice_data["items"]:
        table_data.append([item["description"], f"{item['value']:.2f}"])

    table_data.append(["Total", f"{invoice_data['amount']:.2f}"])

    invoice_table = Table(table_data, colWidths=[350, 150])
    invoice_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
    ]))

    story.append(invoice_table)

    # Construção do documento
    doc.build(story)
    buffer.seek(0)
    return buffer


# ------------------------------------------------------------------------------
# Rota do Endpoint
# ------------------------------------------------------------------------------

@app.get(
    "/api/v1/invoices/{invoice_id}/pdf",
    response_class=StreamingResponse,
    summary="Download do PDF da fatura",
    tags=["Invoices"])
def download_invoice_pdf(
    invoice_id: str,
    current_user: Annotated[UserContext, Depends(get_current_user)]):
    """
    Busca a fatura validando o locatário e retorna o PDF correspondente.
    """
    # 1. Consulta segura com validação de Multitenancy
    invoice = get_invoice_by_id(invoice_id=invoice_id, tenant_id=current_user.tenant_id)

    if not invoice:
        # Resposta genérica 404 para não expor se o recurso existe sob outro tenant
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fatura não encontrada."
        )

    # 2. Geração do relatório em memória
    pdf_buffer = generate_invoice_pdf(invoice)

    # 3. Resposta com headers seguros de download
    filename = f"fatura_{invoice_id}.pdf"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff"
    }

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers=headers
    )