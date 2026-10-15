from datetime import date
from decimal import Decimal
from enum import Enum
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import asc, desc, func, select
from sqlalchemy.orm import Session

# Dependências e modelos já existentes na aplicação (ajuste os imports):
from app.auth import AuthenticatedUser, get_current_user
from app.database import get_db
from app.models import Contract

router = APIRouter(prefix="/contracts", tags=["contracts"])


# ---------------------------------------------------------------------------
# Parâmetros de ordenação: lista branca explícita
# ---------------------------------------------------------------------------
# O valor recebido na requisição NUNCA é usado diretamente para montar a query.
# Ele é validado contra este Enum e traduzido para um atributo do modelo.
class ContractSortField(str, Enum):
    id = "id"
    number = "number"
    title = "title"
    status = "status"
    value = "value"
    start_date = "start_date"
    end_date = "end_date"
    created_at = "created_at"


class SortDirection(str, Enum):
    asc = "asc"
    desc = "desc"


SORTABLE_COLUMNS = {
    ContractSortField.id: Contract.id,
    ContractSortField.number: Contract.number,
    ContractSortField.title: Contract.title,
    ContractSortField.status: Contract.status,
    ContractSortField.value: Contract.value,
    ContractSortField.start_date: Contract.start_date,
    ContractSortField.end_date: Contract.end_date,
    ContractSortField.created_at: Contract.created_at,
}


# ---------------------------------------------------------------------------
# Schemas de resposta (company_id deliberadamente não é exposto)
# ---------------------------------------------------------------------------
class ContractOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    number: str
    title: str
    status: str
    value: Decimal
    start_date: date
    end_date: date | None
    created_at: date


class ContractListOut(BaseModel):
    items: list[ContractOut]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------
@router.get("", response_model=ContractListOut)
def list_contracts(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    sort_by: Annotated[ContractSortField, Query()] = ContractSortField.created_at,
    direction: Annotated[SortDirection, Query()] = SortDirection.desc,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ContractListOut:
    """
    Lista os contratos da empresa do usuário autenticado.

    Exemplo: GET /contracts?sort_by=value&direction=desc&limit=50
    """
    # 1) Isolamento de tenant: o company_id vem SEMPRE da identidade autenticada
    #    (token/sessão), nunca de parâmetros da requisição.
    tenant_filter = Contract.company_id == user.company_id

    # 2) Ordenação: coluna e direção já validadas pelos Enums acima.
    column = SORTABLE_COLUMNS[sort_by]
    order = asc(column) if direction is SortDirection.asc else desc(column)

    # 3) Desempate por id garante ordem determinística (paginação estável).
    stmt = (
        select(Contract)
        .where(tenant_filter)
        .order_by(order, asc(Contract.id))
        .limit(limit)
        .offset(offset)
    )

    total = db.scalar(
        select(func.count()).select_from(Contract).where(tenant_filter)
    ) or 0

    items = db.scalars(stmt).all()

    return ContractListOut(
        items=[ContractOut.model_validate(c) for c in items],
        total=total,
        limit=limit,
        offset=offset,
    )