from datetime import date
from decimal import Decimal
from io import BytesIO

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import StreamingResponse
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
from sqlalchemy import select
from sqlalchemy.orm import Session

# Ajuste estes imports aos módulos do seu projeto.
from database import get_db
from models import Fatura
from auth import get_current_user


app = FastAPI()


def formatar_moeda(valor: Decimal) -> str:
    """Formata valores monetários no padrão brasileiro."""
    return f"R$ {valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def gerar_pdf(fatura: Fatura) -> BytesIO:
    """Gera o relatório da fatura e retorna o PDF em memória."""
    buffer = BytesIO()

    documento = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title=f"Relatorio da Fatura {fatura.id}",
    )

    estilos = getSampleStyleSheet()
    conteudo = []

    conteudo.append(
        Paragraph("RELATÓRIO DE FATURA", estilos["Title"])
    )
    conteudo.append(Spacer(1, 10 * mm))

    dados = [
        ["Campo", "Informação"],
        ["Número da fatura", str(fatura.id)],
        ["Cliente", str(fatura.cliente_nome)],
        ["Data de emissão", fatura.data_emissao.strftime("%d/%m/%Y")],
        ["Vencimento", fatura.data_vencimento.strftime("%d/%m/%Y")],
        ["Status", str(fatura.status)],
        ["Valor total", formatar_moeda(Decimal(str(fatura.valor_total)))],
    ]

    tabela = Table(dados, colWidths=[55 * mm, 105 * mm])
    tabela.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E78")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#EAF0F6")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ])
    )

    conteudo.append(tabela)
    documento.build(conteudo)

    buffer.seek(0)
    return buffer


@app.get(
    "/faturas/{fatura_id}/relatorio",
    response_class=StreamingResponse,
    summary="Baixar relatório de uma fatura em PDF",
)
def baixar_relatorio_fatura(
    fatura_id: int,
    db: Session = Depends(get_db),
    usuario=Depends(get_current_user),
):
    # O tenant deve vir da identidade autenticada,
    # nunca de um parâmetro enviado pelo cliente.
    tenant_id = usuario.tenant_id

    consulta = select(Fatura).where(
        Fatura.id == fatura_id,
        Fatura.tenant_id == tenant_id,
    )

    fatura = db.scalars(consulta).first()

    if fatura is None:
        # Não revela se a fatura existe em outro tenant.
        raise HTTPException(
            status_code=404,
            detail="Fatura não encontrada.",
        )

    pdf = gerar_pdf(fatura)

    return StreamingResponse(
        pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="fatura_{fatura.id}.pdf"'
            ),
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )