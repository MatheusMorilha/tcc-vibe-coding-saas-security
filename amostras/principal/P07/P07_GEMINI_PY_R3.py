from io import BytesIO
from typing import Annotated, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = FastAPI(title="SaaS Invoice API")

# ------------------------------------------------------------------------------
# DUMMY AUTH & MULTI-TENANCY HELPERS
# ------------------------------------------------------------------------------
class UserContext:
    def __init__(self, user_id: str, company_id: str):
        self.user_id = user_id
        self.company_id = company_id  # ID do locatário (Tenant)

def get_current_user() -> UserContext:
    """
    Simula a extração e validação do JWT enviado na requisição.
    Retorna o usuário logado com o ID da empresa (company_id) associada.
    """
    return UserContext(user_id="usr_999", company_id="empresa_abc")

# Banco de dados simulado (Multi-tenant)
INVOICES_DB: Dict[str, Dict[str, Any]] = {
    "fat_12345": {
        "id": "fat_12345",
        "company_id": "empresa_abc",  # Pertence ao mesmo tenant do usuário
        "customer_name": "Tecnologia e Serviços Ltda",
        "customer_document": "12.345.678/0001-90",
        "issue_date": "07/10/2026",
        "due_date": "15/10/2026",
        "items": [
            {"description": "Assinatura SaaS - Plano Enterprise (Outubro/2026)", "qty": 1, "price": 1500.00},
            {"description": "Usuários Adicionais (10 licenças)", "qty": 10, "price": 25.00},
            {"description": "Suporte Prioritário 24/7", "qty": 1, "price": 300.00},
        ]
    }
}

# ------------------------------------------------------------------------------
# SERVIÇO DE GERAÇÃO DO PDF (REPORTLAB)
# ------------------------------------------------------------------------------
def generate_invoice_pdf(invoice: Dict[str, Any]) -> BytesIO:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    story = []
    styles = getSampleStyleSheet()

    # Estilos customizados
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor('#1E293B'))
    label_bold = ParagraphStyle('LabelBold', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#0F172A'))
    normal_style = ParagraphStyle('NormalStyle', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#334155'))

    # Cabeçalho
    story.append(Paragraph(f"FATURA #{invoice['id'].upper()}", title_style))
    story.append(Spacer(1, 12))

    # Dados da Fatura / Cliente
    info_data = [
        [Paragraph("<b>Cliente:</b>", label_bold), Paragraph(invoice["customer_name"], normal_style)],
        [Paragraph("<b>CNPJ/CPF:</b>", label_bold), Paragraph(invoice["customer_document"], normal_style)],
        [Paragraph("<b>Data de Emissão:</b>", label_bold), Paragraph(invoice["issue_date"], normal_style)],
        [Paragraph("<b>Data de Vencimento:</b>", label_bold), Paragraph(invoice["due_date"], normal_style)]
    ]
    info_table = Table(info_data, colWidths=[1.5 * inch, 4.5 * inch])
    info_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 20))

    # Tabela de Itens
    items_header = [Paragraph("<b>Descrição</b>", label_bold), Paragraph("<b>Qtd</b>", label_bold), Paragraph("<b>Preço Unit.</b>", label_bold), Paragraph("<b>Total</b>", label_bold)]
    items_data = [items_header]

    total_amount = 0.0
    for item in invoice["items"]:
        subtotal = item["qty"] * item["price"]
        total_amount += subtotal
        items_data.append([
            Paragraph(item["description"], normal_style),
            Paragraph(str(item["qty"]), normal_style),
            Paragraph(f"R$ {item['price']:.2f}", normal_style),
            Paragraph(f"R$ {subtotal:.2f}", normal_style)
        ])

    # Linha do Total
    items_data.append([
        Paragraph("<b>Total a Pagar</b>", label_bold),
        "", "",
        Paragraph(f"<b>R$ {total_amount:.2f}</b>", label_bold)
    ])

    items_table = Table(items_data, colWidths=[3.5 * inch, 0.8 * inch, 1.2 * inch, 1.2 * inch])
    items_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
        ('LINEBELOW', (0, 0), (-1, 0), 1, colors.HexColor('#CBD5E1')),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('SPAN', (0, -1), (2, -1)),  # Mescla as primeiras 3 colunas na última linha
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#F8FAFC')),
        ('LINEABOVE', (0, -1), (-1, -1), 1, colors.HexColor('#94A3B8')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(items_table)

    # Constrói o PDF e reseta a posição do ponteiro no buffer
    doc.build(story)
    buffer.seek(0)
    return buffer

# ------------------------------------------------------------------------------
# ROTA DA API (DOWNLOAD DO PDF)
# ------------------------------------------------------------------------------
@app.get(
    "/api/v1/invoices/{invoice_id}/download",
    response_class=StreamingResponse,
    summary="Download do PDF da Fatura",
    tags=["Invoices"])
async def download_invoice(
    invoice_id: str,
    current_user: Annotated[UserContext, Depends(get_current_user)]):
    # 1. Busca da fatura no banco de dados
    invoice = INVOICES_DB.get(invoice_id)
    if not invoice:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fatura não encontrada."
        )

    # 2. Validação Estrita de Multi-Tenancy (Isolação por Locatário)
    if invoice["company_id"] != current_user.company_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: esta fatura pertence a outra empresa cliente."
        )

    # 3. Geração em memória
    pdf_buffer = generate_invoice_pdf(invoice)

    # 4. Retorno do arquivo via Streaming
    filename = f"fatura_{invoice_id}.pdf"
    headers = {
        "Content-Disposition": f"attachment; filename={filename}"
    }

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers=headers
    )