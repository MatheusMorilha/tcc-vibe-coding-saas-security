from datetime import date
from decimal import Decimal
from enum import Enum
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Date, ForeignKey, Numeric, String, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class Contract(Base):
    __tablename__ = "contracts"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Coluna discriminadora do tenant: indexada e obrigatória
    company_id: Mapped[int] = mapped_column(
        ForeignKey("companies.id"), index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(255))
    counterparty: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32))
    value: Mapped[Decimal] = mapped_column(Numeric(14, 2))
    start_date: Mapped[date] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    # Exemplo de coluna interna que NÃO deve ser exposta nem ordenável
    internal_notes: Mapped[str | None] = mapped_column(String(2000), nullable=True)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ContractOut(BaseModel):
    """Apenas os campos que podem sair pela API (internal_notes fica de fora)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    counterparty: str
    status: str
    value: Decimal
    start_date: date
    end_date: date | None


class ContractPage(BaseModel):
    items: list[ContractOut]
    total: int
    page: int
    page_size: int


class SortDirection(str, Enum):
    asc = "asc"
    desc = "desc"


# ---------------------------------------------------------------------------
# Lista branca de colunas ordenáveis
# O cliente envia apenas a CHAVE; a coluna real vem deste mapa.
# ---------------------------------------------------------------------------

SORTABLE_COLUMNS = {
    "id": Contract.id,
    "title": Contract.title,
    "counterparty": Contract.counterparty,
    "status": Contract.status,
    "value": Contract.value,
    "start_date": Contract.start_date,
    "end_date": Contract.end_date,
}
DEFAULT_SORT = "start_date"


# ---------------------------------------------------------------------------
# Dependências (adapte à sua infraestrutura)
# ---------------------------------------------------------------------------


class CurrentUser(BaseModel):
    id: int
    company_id: int
    subscription_active: bool


def get_db() -> Session:  # pragma: no cover - substitua pela sua sessão real
    raise NotImplementedError


def get_current_user() -> CurrentUser:  # pragma: no cover
    """Deve validar o token (JWT/sessão) e carregar o usuário autenticado."""
    raise NotImplementedError


def require_active_subscription(
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> CurrentUser:
    if not user.subscription_active:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Assinatura inativa.",
        )
    return user


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/contracts", tags=["contracts"])


@router.get("", response_model=ContractPage)
def list_contracts(
    user: Annotated[CurrentUser, Depends(require_active_subscription)],
    db: Annotated[Session, Depends(get_db)],
    sort_by: str = Query(DEFAULT_SORT, description="Coluna de ordenação"),
    direction: SortDirection = Query(SortDirection.asc, description="asc ou desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> ContractPage:
    sort_column = SORTABLE_COLUMNS.get(sort_by)
    if sort_column is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"sort_by inválido. Valores aceitos: {sorted(SORTABLE_COLUMNS)}",
        )

    order_expr = sort_column.asc() if direction is SortDirection.asc else sort_column.desc()
    # nulls_last evita que contratos sem end_date dominem o topo/fim de forma inconsistente
    order_expr = order_expr.nulls_last()

    # Filtro de tenant SEMPRE aplicado, com o company_id vindo do usuário autenticado
    tenant_filter = Contract.company_id == user.company_id

    total = db.scalar(select(func.count()).select_from(Contract).where(tenant_filter)) or 0

    stmt = (
        select(Contract)
        .where(tenant_filter)
        # id como desempate garante paginação determinística
        .order_by(order_expr, Contract.id.asc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    rows = db.scalars(stmt).all()

    return ContractPage(
        items=[ContractOut.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )