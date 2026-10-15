"""
Rota de exportação de clientes para planilha (.xlsx) em plataforma SaaS multilocatária.

Decisões de segurança:
- O tenant (company_id) é obtido SOMENTE do usuário autenticado, nunca da requisição.
- Exige permissão explícita de exportação e plano que inclua o recurso.
- Neutraliza "formula injection" (CSV/Excel injection) nas células.
- Remove caracteres ilegais em XML que quebrariam o arquivo.
- Limite máximo de linhas e leitura em lotes para proteger memória e o banco.
- Nome do arquivo gerado pelo servidor (sem dados controlados pelo usuário).
- Registro de auditoria (dados cadastrais podem conter dados pessoais - LGPD).
"""

import logging
import re
from datetime import datetime, timezone
from io import BytesIO

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from sqlalchemy import select
from sqlalchemy.orm import Session

# Ajuste os imports abaixo à estrutura real do projeto
from app.auth import get_current_user          # retorna o usuário autenticado
from app.database import get_db                # sessão SQLAlchemy síncrona
from app.models import Customer, AuditLog      # modelos ORM
from app.schemas import AuthenticatedUser      # .id, .company_id, .permissions, .plan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/customers", tags=["customers"])

XLSX_MEDIA_TYPE = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)
EXPORT_PERMISSION = "customers:export"
MAX_EXPORT_ROWS = 50_000   # teto por exportação (ajuste conforme o plano/infra)
FETCH_BATCH_SIZE = 1_000
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

COLUMNS = [
    ("ID", lambda c: str(c.id)),
    ("Nome / Razão social", lambda c: c.name),
    ("CPF / CNPJ", lambda c: c.document),
    ("E-mail", lambda c: c.email),
    ("Telefone", lambda c: c.phone),
    ("Logradouro", lambda c: c.address_street),
    ("Cidade", lambda c: c.address_city),
    ("UF", lambda c: c.address_state),
    ("CEP", lambda c: c.address_zip),
    ("Cadastrado em", lambda c: c.created_at.strftime("%Y-%m-%d %H:%M:%S") if c.created_at else ""),
]


def _sanitize_cell(value) -> str:
    """Converte para texto seguro: sem caracteres ilegais e sem início de fórmula."""
    if value is None:
        return ""
    text = ILLEGAL_CHARACTERS_RE.sub("", str(value))
    if text.startswith(FORMULA_PREFIXES):
        text = "'" + text  # força o Excel/LibreOffice a tratar como texto
    return text


def _build_workbook(db: Session, company_id) -> tuple[BytesIO, int]:
    """Gera o .xlsx em modo write_only (baixo consumo de memória)."""
    wb = Workbook(write_only=True)
    ws = wb.create_sheet("Clientes")
    ws.append([header for header, _ in COLUMNS])

    # Filtro por tenant SEMPRE presente; ignora registros excluídos logicamente
    stmt = (
        select(Customer)
        .where(Customer.company_id == company_id, Customer.deleted_at.is_(None))
        .order_by(Customer.name, Customer.id)
        .limit(MAX_EXPORT_ROWS + 1)  # +1 para detectar estouro do limite
        .execution_options(yield_per=FETCH_BATCH_SIZE)
    )

    total = 0
    for customer in db.scalars(stmt):
        if total >= MAX_EXPORT_ROWS:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=(
                    f"A exportação excede o limite de {MAX_EXPORT_ROWS} registros. "
                    "Aplique filtros ou entre em contato com o suporte."
                ),
            )
        ws.append([_sanitize_cell(getter(customer)) for _, getter in COLUMNS])
        total += 1

    buffer = BytesIO()
    wb.save(buffer)
    buffer.seek(0)
    return buffer, total


@router.get(
    "/export",
    response_class=StreamingResponse,
    summary="Exporta os clientes da empresa autenticada para .xlsx",
)
def export_customers(
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(get_current_user),
):
    # 1) Autorização: permissão do usuário
    if EXPORT_PERMISSION not in user.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para exportar clientes.",
        )

    # 2) Plano de assinatura ativo e com o recurso habilitado
    if not user.plan or not user.plan.is_active or "export" not in user.plan.features:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Seu plano atual não inclui a exportação de dados.",
        )

    # 3) Geração (company_id vem do token/sessão, nunca de query/path/body)
    try:
        buffer, total = _build_workbook(db, user.company_id)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Falha ao exportar clientes (company_id=%s)", user.company_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível gerar a planilha. Tente novamente.",
        )

    # 4) Auditoria
    db.add(
        AuditLog(
            company_id=user.company_id,
            user_id=user.id,
            action="customers.export",
            details={"rows": total},
        )
    )
    db.commit()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"clientes_{timestamp}.xlsx"

    return StreamingResponse(
        buffer,
        media_type=XLSX_MEDIA_TYPE,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",  # evita cache de dados pessoais
            "X-Content-Type-Options": "nosniff",
        },
    )