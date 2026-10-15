"""Rota de download do PDF de fatura (multilocatário)."""
from __future__ import annotations

import logging
import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.auth import CurrentUser, get_current_user          # autenticação (JWT/sessão)
from app.db import get_db                                   # sessão do SQLAlchemy
from app.models import Invoice, Tenant                      # modelos com coluna tenant_id
from app.services.invoice_pdf import build_invoice_pdf

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/invoices", tags=["invoices"])


def _safe_filename(number: str) -> str:
    """Evita injeção de cabeçalho/path traversal no Content-Disposition."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", number)[:60] or "fatura"


@router.get(
    "/{invoice_id}/pdf",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}}}, 404: {"description": "Fatura não encontrada"}},
)
def download_invoice_pdf(
    invoice_id: UUID,
    user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    # Isolamento de tenant: o tenant vem SEMPRE da identidade autenticada,
    # nunca de parâmetro/cabeçalho enviado pelo cliente, e entra no WHERE da consulta.
    invoice = db.scalars(
        select(Invoice)
        .where(Invoice.id == invoice_id, Invoice.tenant_id == user.tenant_id)
        .options(selectinload(Invoice.items))
    ).one_or_none()

    # 404 (e não 403) para faturas de outros tenants: não revela que o ID existe.
    if invoice is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Fatura não encontrada.")

    tenant = db.get(Tenant, user.tenant_id)
    pdf_bytes = build_invoice_pdf(invoice, tenant_name=tenant.name if tenant else "")

    logger.info("invoice_pdf_downloaded tenant=%s user=%s invoice=%s", user.tenant_id, user.id, invoice.id)

    filename = f"fatura-{_safe_filename(invoice.number)}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "private, no-store",   # evita cache em proxies compartilhados
            "X-Content-Type-Options": "nosniff",
        },
    )