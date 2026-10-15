import io
from typing import Dict, Any
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = FastAPI(title="SaaS Invoice API")

# --- Schemas ---
class UserContext(BaseModel):
    user_id: str
    tenant_id: str

# --- Middleware / Dependency Mock para Auth & Multi-tenancy ---
def get_current_user() -> UserContext:
    """
    Simula a extração do contexto do usuário autenticado via token JWT.
    Em produção, valide o token e extraia o tenant_id.
    """
    return UserContext(user_id="usr_12345", tenant_id="tenant_acme_corp")

# --- Mock de Dados ---
def fetch_invoice_from_db(invoice_id: str, tenant_id: str) -> Dict[str, Any]:
    """
    Simula a consulta no banco de dados.
    IMPORTANTE: A query DEVE obrigatoriamente filtrar por invoice_id AND tenant_id.
    """
    mock_db = {
        "inv_9988": {
            "invoice_id": "inv_9988",
            "tenant_id": "tenant_acme_corp",
            "company_name": "Acme Corp Ltd.",
            "customer_name": "Empresa Cliente X",
            "date": "2026-10-07",
            "due_date": "2026-10-20",
            "items": [
                {"description": "Assinatura Plano Enterprise (Out/2026)", "amount": 1500.00},
                {"description": "Usuários Adicionais (5x)", "amount": 250.00},
            ],
            "total_amount": 1750.00,
            "status": "PAID"
        }
    }

    invoice = mock_db.get(invoice_id)
    # Validação de isolamento do tenant
    if not invoice or invoice["tenant_id"] != tenant_id:
        return None
    return invoice

# --- Função Utilitária para Geração do PDF ---
def generate_invoice_pdf(invoice_data: Dict[str, Any]) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    elements = []
    styles = getSampleStyleSheet()

    # Estilos customizados
    title_style = ParagraphStyle(
        'InvoiceTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=12
    )
    normal_style = styles['Normal']

    # Cabeçalho
    elements.append(Paragraph(f"FATURA #{invoice_data['invoice_id']}", title_style))
    elements.append(Paragraph(f"<b>Empresa:</b> {invoice_data['company_name']}", normal_style))
    elements.append(Paragraph(f"<b>Cliente:</b> {invoice_data['customer_name']}", normal_style))
    elements.append(Paragraph(f"<b>Data de Emissão:</b> {invoice_data['date']}", normal_style))
    elements.append(Paragraph(f"<b>Status:</b> {invoice_data['status']}", normal_style))
    elements.append(Spacer(1, 0.2 * inch))

    # Tabela de Itens
    table_data = [["Descrição", "Valor (R$)"]]
    for item in invoice_data['items']:
        table_data.append([item['description'], f"R$ {item['amount']:.2f}"])

    table_data.append(["TOTAL", f"R$ {invoice_data['total_amount']:.2f}"])

    invoice_table = Table(table_data, colWidths=[3.5 * inch, 2.0 * inch])
    invoice_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#F8FAFC')),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
    ]))

    elements.append(invoice_table)

    # Constrói o documento PDF no buffer em memória
    doc.build(elements)
    buffer.seek(0)
    return buffer

# --- Rota da API ---
@app.get("/api/v1/invoices/{invoice_id}/download", response_class=StreamingResponse)
async def download_invoice_pdf(
    invoice_id: str,
    current_user: UserContext = Depends(get_current_user)):
    """
    Gera e retorna o PDF de uma fatura para download.
    Garante que o usuário só acesse faturas do seu próprio tenant.
    """
    # 1. Busca os dados garantindo o isolamento multilocatário
    invoice = fetch_invoice_from_db(invoice_id, current_user.tenant_id)

    if not invoice:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fatura não encontrada ou acesso não autorizado."
        )

    # 2. Gera o PDF em memória
    pdf_buffer = generate_invoice_pdf(invoice)

    # 3. Define os cabeçalhos da resposta HTTP para download
    filename = f"fatura_{invoice_id}.pdf"
    headers = {
        'Content-Disposition': f'attachment; filename="{filename}"'
    }

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers=headers
    )