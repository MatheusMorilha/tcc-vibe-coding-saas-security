import io
from datetime import datetime
from decimal import Decimal
from typing import List, Optional

from fastapi import FastAPI, Header, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = FastAPI(title="SaaS Invoice API")


# ==========================================
# Modelos de Dados (Schemas)
# ==========================================
class ItemFatura(BaseModel):
    descricao: str
    quantidade: int
    valor_unitario: Decimal


class DadosFatura(BaseModel):
    id_fatura: str
    nome_empresa: str
    documento_empresa: str  # CNPJ / CPF
    data_emissao: datetime
    data_vencimento: datetime
    itens: List[ItemFatura]
    observacoes: Optional[str] = None


# ==========================================
# Função Utilitária para Gerar o PDF
# ==========================================
def gerar_pdf_fatura(dados: DadosFatura) -> io.BytesIO:
    """Gera um PDF formatado em memória utilizando o ReportLab."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm
    )

    styles = getSampleStyleSheet()

    # Estilos customizados
    style_title = ParagraphStyle(
        'InvoiceTitle',
        parent=styles['Heading1'],
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=12
    )
    style_normal = styles['Normal']
    style_bold = ParagraphStyle('BoldStyle', parent=style_normal, fontName='Helvetica-Bold')

    story = []

    # Cabeçalho da Fatura
    story.append(Paragraph(f"FATURA #{dados.id_fatura}", style_title))
    story.append(Spacer(1, 0.2 * cm))

    # Informações do Cliente e Emissão
    info_data = [
        [
            Paragraph(f"<b>Empresa Cliente:</b> {dados.nome_empresa}", style_normal),
            Paragraph(f"<b>Data de Emissão:</b> {dados.data_emissao.strftime('%d/%m/%Y')}", style_normal)
        ],
        [
            Paragraph(f"<b>CNPJ/CPF:</b> {dados.documento_empresa}", style_normal),
            Paragraph(f"<b>Vencimento:</b> {dados.data_vencimento.strftime('%d/%m/%Y')}", style_normal)
        ]
    ]

    info_table = Table(info_data, colWidths=[10 * cm, 8 * cm])
    info_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.8 * cm))

    # Tabela de Itens
    tabela_itens = [["Descrição", "Qtd", "Valor Unit.", "Total"]]
    valor_total_fatura = Decimal("0.00")

    for item in dados.itens:
        total_item = item.quantidade * item.valor_unitario
        valor_total_fatura += total_item
        tabela_itens.append([
            item.descricao,
            str(item.quantidade),
            f"R$ {item.valor_unitario:.2f}",
            f"R$ {total_item:.2f}"
        ])

    # Linha do Total Geral
    tabela_itens.append(["", "", "Total Faturado:", f"R$ {valor_total_fatura:.2f}"])

    col_widths = [9.5 * cm, 2 * cm, 3.2 * cm, 3.3 * cm]
    table = Table(tabela_itens, colWidths=col_widths)

    table_style = TableStyle([
        # Cabeçalho da Tabela
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),
        ('GRID', (0, 0), (-1, -2), 0.5, colors.HexColor('#E2E8F0')),

        # Destaque do Total
        ('FONTNAME', (2, -1), (-1, -1), 'Helvetica-Bold'),
        ('LINEABOVE', (2, -1), (-1, -1), 1, colors.HexColor('#0F172A')),
    ])
    table.setStyle(table_style)
    story.append(table)

    if dados.observacoes:
        story.append(Spacer(1, 0.8 * cm))
        story.append(Paragraph("<b>Observações:</b>", style_normal))
        story.append(Paragraph(dados.observacoes, style_normal))

    # Constrói o documento PDF
    doc.build(story)
    buffer.seek(0)
    return buffer


# ==========================================
# Rota da API (Endpoint)
# ==========================================
@app.post(
    "/api/v1/faturas/{id_fatura}/pdf",
    summary="Gera e faz o download do relatório de fatura em PDF",
    response_class=StreamingResponse)
async def baixar_pdf_fatura(
    id_fatura: str,
    x_tenant_id: str = Header(..., description="ID do tenant do cliente no SaaS"),
    # Em produção, adicione a verificação do usuário autenticado (JWT/OAuth2) aqui):
    """
    Busca os dados de uma fatura associada ao tenant e retorna o arquivo PDF para download.
    """
    if not x_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Header X-Tenant-ID é obrigatório."
        )

    # --------------------------------------------------------------------------
    # MOCK DE DADOS DO BANCO
    # Em um ambiente real, faria uma consulta ORM filtrando por ID e Tenant:
    # fatura = db.query(Fatura).filter_by(id=id_fatura, tenant_id=x_tenant_id).first()
    # --------------------------------------------------------------------------
    fatura_mock = DadosFatura(
        id_fatura=id_fatura,
        nome_empresa="Tech Solutions Ltda",
        documento_empresa="12.345.678/0001-90",
        data_emissao=datetime.now(),
        data_vencimento=datetime.now(),
        itens=[
            ItemFatura(descricao="Licença SaaS - Plano Enterprise (Mensal)", quantidade=1, valor_unitario=Decimal("1500.00")),
            ItemFatura(descricao="Horas de Suporte Consultivo", quantidade=5, valor_unitario=Decimal("120.00")),
        ],
        observacoes="Pagamento via PIX ou Boleto Bancário até a data do vencimento."
    )

    # Gerar o arquivo PDF em memória (buffer de bytes)
    pdf_buffer = gerar_pdf_fatura(fatura_mock)

    filename = f"fatura_{id_fatura}_{x_tenant_id}.pdf"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )