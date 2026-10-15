from enum import Enum
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import asc, desc

# Importações hipotéticas das dependências da aplicação
from app.database import get_db
from app.models import Contract
from app.auth import get_current_user, UserContext

router = APIRouter(prefix="/contracts", tags=["Contracts"])


# Enums para restringir e validar ordenação de forma segura
class ContractSortColumn(str, Enum):
    TITLE = "title"
    STATUS = "status"
    CREATED_AT = "created_at"
    VALUE = "value"


class SortOrder(str, Enum):
    ASC = "asc"
    DESC = "desc"


# Schemas Pydantic para Serialização
class ContractResponse(BaseModel):
    id: int
    title: str
    value: float
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/", response_model=List[ContractResponse])
def list_company_contracts(
    sort_by: ContractSortColumn = Query(
        default=ContractSortColumn.CREATED_AT,
        description="Coluna para ordenação dos contratos"),
    order: SortOrder = Query(
        default=SortOrder.DESC,
        description="Direção da ordenação (asc ou desc)"),
    limit: int = Query(default=20, ge=1, le=100, description="Quantidade de registros por página"),
    offset: int = Query(default=0, ge=0, description="Offset de paginação"),
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user)):
    """
    Lista os contratos pertencentes exclusivamente à empresa do usuário autenticado,
    permitindo ordenação por coluna e direção dinâmicas.
    """
    tenant_id = current_user.company_id

    # 1. Mapeamento explícito para prevenir SQL Injection ou referência a atributos inválidos
    column_mapping = {
        ContractSortColumn.TITLE: Contract.title,
        ContractSortColumn.STATUS: Contract.status,
        ContractSortColumn.CREATED_AT: Contract.created_at,
        ContractSortColumn.VALUE: Contract.value,
    }

    sort_column = column_mapping.get(sort_by)

    # 2. Definição da direção de ordenação
    direction = desc if order == SortOrder.DESC else asc

    # 3. Construção da query isolada por tenant (Isolamento Multi-tenant)
    query = (
        db.query(Contract)
        .filter(Contract.company_id == tenant_id)
        .order_by(direction(sort_column))
        .offset(offset)
        .limit(limit)
    )

    contracts = query.all()
    return contracts