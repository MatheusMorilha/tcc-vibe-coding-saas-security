"""
Rota: GET /api/v1/invoices/{invoice_id}/pdf

Gera o PDF de uma fatura e o devolve para download.

Controles de segurança (OWASP Top 10:2021):
- A01 Broken Access Control: autenticação obrigatória, RBAC e isolamento
  multilocatário (tenant_id vem do token, nunca do cliente; o filtro está na
  própria query). Fatura de outro tenant => 404 (não revela existência).
- A02 Cryptographic Failures: Cache-Control: no-store (dado financeiro não deve
  ficar em cache de proxy/navegador); TLS/HSTS ficam no gateway.
- A03 Injection: ORM com parâmetros vinculados; todo texto vindo do banco é
  escapado antes de entrar no markup do ReportLab; nome de arquivo é gerado
  pelo servidor (UUID), sem entrada do usuário (evita header injection).
- A04 Insecure Design: limite de itens por PDF (evita DoS por geração pesada);
  verificação de entitlement do plano de assinatura.
- A05 Security Misconfiguration: headers defensivos na resposta, sem detalhes
  de erro internos.
- A07/A09: auditoria de acesso/negação, sem logar dados sensíveis.
"""
from __future__ import annotations

import logging
import uuid
from decimal import ROUND_HALF_UP, Decimal
from io import BytesIO
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException, Response, status
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

# Módulos já existentes na aplicação (ajuste os caminhos ao seu projeto):
from app.auth import AuthenticatedUser, get_current_user  # valida JWT/sessão
from app.db import get_db
from app.models import Invoice

logger = logging.getLogger("app.invoice_pdf")
audit_logger = logging.getLogger("app.audit")

router = APIRouter(prefix="/api/v1/invoices", tags=["invoices"])

ALLOWED_ROLES = {"admin", "finance", "billing_viewer"}
REQUIRED_PLAN_FEATURE = "pdf_reports"
MAX_ITEMS_PER_PDF = 500

_styles = getSampleStyleSheet()
_CENT = Decimal("0.01")


def _money(value: Decimal | None, currency: str) -> str:
    q = (value or Decimal("0")).quantize(_CENT, rounding=ROUND_HALF_UP)
    return f"{escape(currency)} {q:,.2f}"


def _p(text: object, style: str = "Normal") -> Paragraph:
    # escape() neutraliza <, >, & -> impede injeção de markup do ReportLab
    return Paragraph(escape(str(text if text is not None else "")), _styles[style])


def _build_pdf(inv: Invoice) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Fatura {inv.number}",
        author="Plataforma",
    )

    story = [
        _p(f"Fatura nº {inv.number}", "Title"),
        _p(f"Cliente: {inv.customer_name}"),
        _p(f"CNPJ/CPF: {inv.customer_tax_id}"),
        _p(f"Emissão: {inv.issue_date:%d/%m/%Y}   Vencimento: {inv.due_date:%d/%m/%Y}"),
        _p(f"Status: {inv.status}"),
        Spacer(1, 8 * mm),
    ]

    rows = [["Descrição", "Qtd", "Preço unit.", "Subtotal"]]
    for it in inv.items:
        subtotal = (it.quantity * it.unit_price).quantize(_CENT, ROUND_HALF_UP)
        rows.append(
            [
                _p(it.description),
                f"{it.quantity:g}",
                _money(it.unit_price, inv.currency),
                _money(subtotal, inv.currency),
            ]
        )
    rows.append(["", "", "Total", _money(inv.total, inv.currency)])

    table = Table(rows, colWidths=[85 * mm, 20 * mm, 35 * mm, 35 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -2), 0.25, colors.grey),
                ("FONTNAME", (-2, -1), (-1, -1), "Helvetica-Bold"),
            ]
        )
    )
    story.append(table)
    doc.build(story)
    return buf.getvalue()


@router.get(
    "/{invoice_id}/pdf",
    response_class=Response,
    responses={
        200: {"content": {"application/pdf": {}}},
        401: {"description": "Não autenticado"},
        403: {"description": "Sem permissão ou plano sem o recurso"},
        404: {"description": "Fatura não encontrada"},
        413: {"description": "Fatura excede o limite para geração de PDF"},
    },
)
def download_invoice_pdf(
    invoice_id: uuid.UUID,  # validação de tipo: rejeita qualquer valor não-UUID
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Response:
    # --- A01: autorização por função e por plano -------------------------
    if not (ALLOWED_ROLES & set(user.roles)):
        audit_logger.warning(
            "pdf_denied reason=role user=%s tenant=%s invoice=%s",
            user.id, user.tenant_id, invoice_id,
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Acesso negado.")

    if REQUIRED_PLAN_FEATURE not in user.plan_features:
        audit_logger.info(
            "pdf_denied reason=plan user=%s tenant=%s", user.id, user.tenant_id
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Recurso indisponível no plano atual."
        )

    # --- A01/A03: isolamento de tenant na própria consulta ---------------
    stmt = (
        select(Invoice)
        .options(selectinload(Invoice.items))
        .where(
            Invoice.id == invoice_id,
            Invoice.tenant_id == user.tenant_id,  # vem do token, não do request
        )
    )
    invoice = db.execute(stmt).scalar_one_or_none()

    if invoice is None:
        # Mesma resposta para "não existe" e "é de outro tenant"
        audit_logger.info(
            "pdf_not_found user=%s tenant=%s invoice=%s",
            user.id, user.tenant_id, invoice_id,
        )
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Fatura não encontrada.")

    # --- A04: limite contra abuso de recursos ----------------------------
    if len(invoice.items) > MAX_ITEMS_PER_PDF:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            "Fatura grande demais para gerar PDF.",
        )

    try:
        pdf_bytes = _build_pdf(invoice)
    except Exception:
        # A05/A09: loga o detalhe internamente, devolve mensagem genérica
        logger.exception("pdf_generation_failed invoice=%s tenant=%s",
                         invoice_id, user.tenant_id)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "Não foi possível gerar o PDF."
        )

    audit_logger.info(
        "pdf_generated user=%s tenant=%s invoice=%s", user.id, user.tenant_id, invoice_id
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            # nome do arquivo controlado pelo servidor (sem dado do usuário)
            "Content-Disposition": f'attachment; filename="fatura-{invoice.id}.pdf"',
            "Cache-Control": "no-store, private",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'",
        },
    )