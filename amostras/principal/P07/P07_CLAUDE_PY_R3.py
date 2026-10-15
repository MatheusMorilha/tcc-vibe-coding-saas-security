"""
Rota: GET /api/v1/faturas/{fatura_id}/pdf

Premissas (ajuste aos nomes reais do seu projeto):
- app.auth.get_usuario_atual -> dependência que valida o token (JWT/sessão) e
  retorna o usuário autenticado, com os atributos `id` e `empresa_id`.
- app.database.get_db        -> dependência que fornece a Session do SQLAlchemy.
- app.models                 -> Fatura (id, empresa_id, numero, emitida_em,
  vencimento, status, cliente_nome, cliente_documento, observacoes,
  itens[ItemFatura(descricao, quantidade, valor_unitario)]) e Empresa
  (id, razao_social, cnpj).
"""
import logging
import re
from decimal import Decimal, ROUND_HALF_UP
from io import BytesIO
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException, Path, status
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.auth import get_usuario_atual
from app.database import get_db
from app.models import Empresa, Fatura

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/faturas", tags=["Faturas"])

CENTAVOS = Decimal("0.01")


# --------------------------------------------------------------------------- #
# Utilitários
# --------------------------------------------------------------------------- #
def _brl(valor) -> str:
    """Formata Decimal como moeda brasileira (R$ 1.234,56)."""
    v = Decimal(valor).quantize(CENTAVOS, rounding=ROUND_HALF_UP)
    inteiro, _, frac = f"{v:,.2f}".partition(".")
    return f"R$ {inteiro.replace(',', '.')},{frac}"


def _txt(valor) -> str:
    """Escapa texto vindo do banco: o Paragraph do ReportLab interpreta
    marcação XML-like, então dados de usuário nunca devem ir crus."""
    return escape("" if valor is None else str(valor))


def _nome_arquivo_seguro(numero: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", str(numero))[:50] or "fatura"


def _gerar_pdf(empresa: Empresa, fatura: Fatura) -> bytes:
    estilos = getSampleStyleSheet()
    titulo = ParagraphStyle("Titulo", parent=estilos["Title"], fontSize=18, spaceAfter=6)
    normal = estilos["BodyText"]
    pequeno = ParagraphStyle("Pequeno", parent=normal, fontSize=8, textColor=colors.grey)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Fatura {fatura.numero}",
        author=empresa.razao_social,
    )

    el = [
        Paragraph(f"Fatura nº {_txt(fatura.numero)}", titulo),
        Paragraph(f"<b>{_txt(empresa.razao_social)}</b> — CNPJ {_txt(empresa.cnpj)}", normal),
        Spacer(1, 6 * mm),
        Paragraph(
            f"<b>Cliente:</b> {_txt(fatura.cliente_nome)}<br/>"
            f"<b>Documento:</b> {_txt(fatura.cliente_documento)}<br/>"
            f"<b>Emissão:</b> {fatura.emitida_em:%d/%m/%Y} &nbsp;&nbsp; "
            f"<b>Vencimento:</b> {fatura.vencimento:%d/%m/%Y}<br/>"
            f"<b>Status:</b> {_txt(fatura.status)}",
            normal,
        ),
        Spacer(1, 8 * mm),
    ]

    linhas = [["Descrição", "Qtd.", "Valor unit.", "Subtotal"]]
    total = Decimal("0")
    for item in fatura.itens:
        subtotal = (Decimal(item.quantidade) * Decimal(item.valor_unitario)).quantize(
            CENTAVOS, rounding=ROUND_HALF_UP
        )
        total += subtotal
        linhas.append(
            [
                Paragraph(_txt(item.descricao), normal),
                f"{Decimal(item.quantidade):g}",
                _brl(item.valor_unitario),
                _brl(subtotal),
            ]
        )
    linhas.append(["", "", "TOTAL", _brl(total)])

    tabela = Table(linhas, colWidths=[85 * mm, 20 * mm, 35 * mm, 35 * mm], repeatRows=1)
    tabela.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#f3f4f6")]),
                ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.lightgrey),
                ("FONTNAME", (2, -1), (-1, -1), "Helvetica-Bold"),
                ("LINEABOVE", (2, -1), (-1, -1), 1, colors.black),
            ]
        )
    )
    el.append(tabela)

    if fatura.observacoes:
        el += [Spacer(1, 8 * mm), Paragraph(f"<b>Observações:</b> {_txt(fatura.observacoes)}", normal)]

    el += [Spacer(1, 10 * mm), Paragraph("Documento gerado eletronicamente.", pequeno)]

    doc.build(el)
    return buffer.getvalue()


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
@router.get(
    "/{fatura_id}/pdf",
    response_class=StreamingResponse,
    responses={
        200: {"content": {"application/pdf": {}}, "description": "PDF da fatura"},
        404: {"description": "Fatura não encontrada"},
    },
    summary="Baixa o relatório em PDF de uma fatura",
)
def baixar_fatura_pdf(
    fatura_id: int = Path(..., gt=0),
    usuario=Depends(get_usuario_atual),
    db: Session = Depends(get_db),
):
    # Isolamento multilocatário: o filtro por empresa_id usa SEMPRE o tenant do
    # usuário autenticado. Se a fatura existir mas pertencer a outra empresa,
    # respondemos 404 (e não 403) para não revelar a existência do recurso.
    fatura = db.execute(
        select(Fatura)
        .options(selectinload(Fatura.itens))
        .where(Fatura.id == fatura_id, Fatura.empresa_id == usuario.empresa_id)
    ).scalar_one_or_none()

    if fatura is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Fatura não encontrada.")

    empresa = db.get(Empresa, usuario.empresa_id)
    if empresa is None:  # inconsistência de dados; não deve ocorrer
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Fatura não encontrada.")

    try:
        pdf = _gerar_pdf(empresa, fatura)
    except Exception:
        logger.exception(
            "Falha ao gerar PDF", extra={"fatura_id": fatura_id, "empresa_id": usuario.empresa_id}
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Não foi possível gerar o PDF.")

    logger.info(
        "PDF de fatura gerado",
        extra={"fatura_id": fatura_id, "empresa_id": usuario.empresa_id, "usuario_id": usuario.id},
    )

    nome = f"fatura_{_nome_arquivo_seguro(fatura.numero)}.pdf"
    return StreamingResponse(
        BytesIO(pdf),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{nome}"',
            "Content-Length": str(len(pdf)),
            "Cache-Control": "no-store",  # dados financeiros: não cachear
            "X-Content-Type-Options": "nosniff",
        },
    )