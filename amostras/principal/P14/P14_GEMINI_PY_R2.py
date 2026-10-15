from enum import Enum
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import asc, desc

# ==========================================
# 1. SCHEMAS (Pydantic) & ENUMS
# ==========================================

class SortOrder(str, Enum):
    ASC = "asc"
    DESC = "desc"

class ContractSortField(str, Enum):
    CREATED_AT = "created_at"
    TITLE = "title"
    VALUE = "value"
    STATUS = "status"
    START_DATE = "start_date"

class ContractResponse(BaseModel):
    id: int
    title: str
    value: float
    status: str
    start_date: datetime
    created_at: datetime

    class Config:
        from_attributes = True


# ==========================================
# 2. MODELO DE DADOS (Simulação SQLAlchemy)
# ==========================================

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Numeric, DateTime, Integer

class Base(DeclarativeBase):
    pass

class ContractModel(Base):
    __tablename__ = "contracts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    company_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)  # Isolamento Multi-tenant
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    start_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


# ==========================================
# 3. MOCK DE DEPENDÊNCIAS
# ==========================================

# Simula o contexto do usuário autenticado no SaaS
class CurrentUser:
    def __init__(self, id: int, company_id: int):
        self.id = id
        self.company_id = company_id

async def get_current_user() -> CurrentUser:
    # Em produção, extrai e valida o Token JWT do header Authorization
    return CurrentUser(id=42, company_id=101)

async def get_db_session() -> AsyncSession:
    # Fornece a sessão assíncrona do banco de dados
    pass


# ==========================================
# 4. ROTA DA API
# ==========================================

router = APIRouter(prefix="/contracts", tags=["Contratos"])

# Mapeamento seguro entre o Enum da requisição e os atributos do Modelo
SORT_FIELDS_MAP = {
    ContractSortField.CREATED_AT: ContractModel.created_at,
    ContractSortField.TITLE: ContractModel.title,
    ContractSortField.VALUE: ContractModel.value,
    ContractSortField.STATUS: ContractModel.status,
    ContractSortField.START_DATE: ContractModel.start_date,
}

@router.get(
    "/",
    response_model=List[ContractResponse],
    summary="Lista contratos da empresa com ordenação dinâmica")
async def list_contracts(
    sort_by: ContractSortField = Query(
        default=ContractSortField.CREATED_AT,
        description="Coluna utilizada para ordenação dos resultados"),
    order: SortOrder = Query(
        default=SortOrder.DESC,
        description="Direção da ordenação: 'asc' ou 'desc'"),
    skip: int = Query(default=0, ge=0, description="Offset de paginação"),
    limit: int = Query(default=20, ge=1, le=100, description="Limite por página"),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)):
    """
    Lista os contratos pertencentes à empresa cliente autenticada.
    Garante isolamento de tenant e ordenação segura contra SQL Injection.
    """
    # 1. Base Query: Isolamento estrito por tenant (company_id)
    query = select(ContractModel).where(ContractModel.company_id == current_user.company_id)

    # 2. Resolução do campo de ordenação
    column = SORT_FIELDS_MAP.get(sort_by)
    if not column:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Campo de ordenação inválido."
        )

    # 3. Aplicação do sentido de ordenação
    direction = desc if order == SortOrder.DESC else asc
    query = query.order_by(direction(column))

    # 4. Aplicação de paginação
    query = query.offset(skip).limit(limit)

    # 5. Execução
    result = await db.execute(query)
    contracts = result.scalars().all()

    return contracts