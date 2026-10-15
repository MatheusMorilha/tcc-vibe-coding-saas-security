from datetime import date, datetime
from decimal import Decimal
from enum import Enum

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Date, DateTime, Numeric, String, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class Contract(Base):
    __tablename__ = "contracts"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Índice em company_id é essencial: todas as consultas filtram por ele.
    company_id: Mapped[int] = mapped_column(index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255))
    customer_name: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32))
    value: Mapped[Decimal] = mapped_column(Numeric(14, 2))
    start_date: Mapped[date] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    # Campos internos que NÃO devem ser expostos nem usados para ordenar.
    internal_notes: Mapped[str | None] = mapped_column(String(2000), nullable=True)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ContractOut(BaseModel):
    """Schema de saída explícito: só expõe o que pode sair da API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    customer_name: str
    status: str
    value: Decimal
    start_date: date
    end_date: date | None
    created_at: datetime


class ContractListOut(BaseModel):
    items: list[ContractOut]
    total: int
    limit: int
    offset: int


class SortDirection(str, Enum):
    asc = "asc"
    desc = "desc"


# Lista de permissão: nome público -> coluna real.
# O valor recebido na requisição NUNCA é usado diretamente na query.
SORTABLE_COLUMNS = {
    "title": Contract.title,
    "customer_name": Contract.customer_name,
    "status": Contract.status,
    "value": Contract.value,
    "start_date": Contract.start_date,
    "end_date": Contract.end_date,
    "created_at": Contract.created_at,
}

# Gera um Enum a partir da lista de permissão. O FastAPI valida a entrada
# e responde 422 automaticamente para qualquer valor fora da lista.
SortBy = Enum("SortBy", {name: name for name in SORTABLE_COLUMNS}, type=str)


# ---------------------------------------------------------------------------
# Dependências (a serem fornecidas pela aplicação)
# ---------------------------------------------------------------------------


class CurrentUser(BaseModel):
    id: int
    company_id: int


def get_db() -> Session:  # pragma: no cover
    """Retorna uma sessão do SQLAlchemy (implementação da aplicação)."""
    raise NotImplementedError


def get_current_user() -> CurrentUser:  # pragma: no cover
    """Resolve o usuário a partir do token/sessão validado (implementação da aplicação)."""
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/contracts", tags=["contracts"])


@router.get("", response_model=ContractListOut)
def list_contracts(
    sort_by: SortBy = Query(SortBy.created_at, description="Coluna de ordenação"),
    sort_dir: SortDirection = Query(SortDirection.desc, description="asc ou desc"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ContractListOut:
    # Isolamento multitenant: o company_id vem do usuário autenticado,
    # jamais de parâmetro da requisição.
    tenant_filter = Contract.company_id == user.company_id

    column = SORTABLE_COLUMNS[sort_by.value]
    primary_order = column.asc() if sort_dir is SortDirection.asc else column.desc()

    stmt = (
        select(Contract)
        .where(tenant_filter)
        # `id` como critério de desempate garante paginação estável
        # quando há valores repetidos na coluna escolhida.
        .order_by(primary_order, Contract.id.asc())
        .limit(limit)
        .offset(offset)
    )

    total = db.scalar(select(func.count()).select_from(Contract).where(tenant_filter)) or 0
    contracts = db.scalars(stmt).all()

    return ContractListOut(
        items=[ContractOut.model_validate(c) for c in contracts],
        total=total,
        limit=limit,
        offset=offset,
    )