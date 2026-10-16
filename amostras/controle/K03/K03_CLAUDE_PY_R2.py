"""
Rota: GET /api/v1/invoices/{invoice_id}/pdf

Gera o PDF de uma fatura e o devolve como download.

Pontos de integração esperados no projeto (já existentes):
- app.auth.deps.require_permission : valida o token/sessão e retorna um Principal
  (user_id, tenant_id, subscription_active). O tenant_id vem SEMPRE do token,
  nunca do request.
- app.db.session.get_db            : fornece a Session do SQLAlchemy.
- app.models.Invoice               : modelo com tenant_id, items, tenant.
- app.core.rate_limit.limiter      : instância do slowapi (key_func por usuário).
"""
import logging
from decimal import ROUND_HALF_UP, Decimal
from io import BytesIO
from uuid import UUID
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload, selectinload

from app.auth.deps import Principal, require_permission
from app.core.rate_limit import limiter
from app.db.session import get_db
from app.models import Invoice

logger = logging.getLogger("app.invoices")
router = APIRouter(prefix="/api/v1/invoices", tags=["invoices"])

MAX_ITEMS = 500          # A04: limite de recursos para evitar DoS por PDF gigante
MAX_TEXT_LEN = 200       # trunca textos livres antes de renderizar
CENTS = Decimal("0.01")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _safe(value: object, max_len: int = MAX_TEXT_LEN) -> str:
    """
    A03 (Injection): o Paragraph do ReportLab interpreta marcação tipo XML/HTML.
    Todo dado vindo do usuário/banco é escapado e truncado antes de ser
    renderizado, evitando injeção de tags (<font>, <img src=...>, etc.).
    """
    return escape(str(value if value is not None else ""))[:max_len]


def _money(value: Decimal) -> str:
    """Formata Decimal em padrão pt-BR (R$ 1.234,56) sem usar float."""
    q = Decimal(value).quantize(CENTS, rounding=ROUND_HALF_UP)
    s = f"{q:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"R$ {s}"


def _build_pdf(invoice: Invoice) -> bytes:
    """Monta o PDF em memória (nada é gravado em disco; sem imagens remotas -> sem SSRF)."""
    styles = getSampleStyleSheet()
    cell = styles["BodyText"]
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Fatura {_safe(invoice.number, 50)}",
        author="Plataforma",
    )

    story = [
        Paragraph(f"Fatura nº {_safe(invoice.number, 50)}", styles["Title"]),
        Paragraph(f"<b>Emissor:</b> {_safe(invoice.tenant.name)}", cell),
        Paragraph(f"<b>Cliente:</b> {_safe(invoice.customer_name)}", cell),
        Paragraph(f"<b>Documento:</b> {_safe(invoice.customer_tax_id, 30)}", cell),
        Paragraph(f"<b>Emissão:</b> {invoice.issue_date:%d/%m/%Y}", cell),
        Paragraph(f"<b>Vencimento:</b> {invoice.due_date:%d/%m/%Y}", cell),
        Spacer(1, 8 * mm),
    ]

    rows = [["Descrição", "Qtd", "Valor unit.", "Subtotal"]]
    total = Decimal("0")
    for item in invoice.items:
        qty = Decimal(item.quantity)
        unit = Decimal(item.unit_price)
        subtotal = qty * unit          # total recalculado com Decimal, nunca float
        total += subtotal
        rows.append(
            [
                Paragraph(_safe(item.description), cell),
                f"{qty.normalize():f}",
                _money(unit),
                _money(subtotal),
            ]
        )
    rows.append(["", "", "Total", _money(total)])

    table = Table(rows, colWidths=[85 * mm, 20 * mm, 32 * mm, 32 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -2), 0.25, colors.lightgrey),
                ("FONTNAME", (2, -1), (-1, -1), "Helvetica-Bold"),
                ("LINEABOVE", (2, -1), (-1, -1), 0.8, colors.black),
            ]
        )
    )
    story.append(table)
    doc.build(story)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
@router.get(
    "/{invoice_id}/pdf",
    response_class=Response,
    responses={
        200: {"content": {"application/pdf": {}}},
        402: {"description": "Assinatura inativa"},
        404: {"description": "Fatura não encontrada"},
    },
)
@limiter.limit("20/minute")  # A04/A05: mitiga abuso e consumo excessivo de CPU
async def download_invoice_pdf(
    request: Request,                       # exigido pelo slowapi
    invoice_id: UUID,                       # A03: validação de tipo -> 422 se inválido
    principal: Principal = Depends(require_permission("invoices:read")),  # A01/A07
    db: Session = Depends(get_db),
) -> Response:
    # A01: regra de negócio do plano de assinatura
    if not principal.subscription_active:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")

    # A01 (Broken Access Control / IDOR): o filtro por tenant_id é parte da própria
    # consulta. A fatura de outro tenant é indistinguível de uma inexistente.
    # A03: ORM com parâmetros vinculados, sem SQL concatenado.
    stmt = (
        select(Invoice)
        .options(joinedload(Invoice.tenant), selectinload(Invoice.items))
        .where(Invoice.id == invoice_id, Invoice.tenant_id == principal.tenant_id)
    )
    invoice = db.execute(stmt).unique().scalar_one_or_none()

    if invoice is None:
        # A09: registra tentativas (possível enumeração/IDOR) sem vazar dados
        logger.warning(
            "invoice_pdf_not_found",
            extra={"tenant_id": str(principal.tenant_id),
                   "user_id": str(principal.user_id),
                   "invoice_id": str(invoice_id)},
        )
        # 404 (e não 403) para não revelar a existência de faturas de outros tenants
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Fatura não encontrada.")

    if len(invoice.items) > MAX_ITEMS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Fatura excede o limite de itens para geração de PDF.",
        )

    try:
        # Geração é CPU-bound e síncrona: executa fora do event loop
        pdf_bytes = await run_in_threadpool(_build_pdf, invoice)
    except Exception:
        # A05/A09: detalhes só no log; resposta genérica ao cliente
        logger.exception("invoice_pdf_generation_failed",
                         extra={"tenant_id": str(principal.tenant_id),
                                "invoice_id": str(invoice_id)})
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            "Não foi possível gerar o PDF.")

    logger.info(
        "invoice_pdf_generated",
        extra={"tenant_id": str(principal.tenant_id),
               "user_id": str(principal.user_id),
               "invoice_id": str(invoice.id)},
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            # Nome do arquivo derivado de UUID (nunca de input): sem header injection
            "Content-Disposition": f'attachment; filename="fatura-{invoice.id}.pdf"',
            "Cache-Control": "no-store, private",   # dado sensível: sem cache em proxies
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'",
        },
    )