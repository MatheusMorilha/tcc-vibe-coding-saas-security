from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from sqlalchemy import select

# ------------------------------------------------------------------------------
# Schemas (Pydantic)
# ------------------------------------------------------------------------------
class CustomerResponse(BaseModel):
    id: int
    name: str
    document: str
    subscription_plan: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class PaginatedCustomersResponse(BaseModel):
    items: List[CustomerResponse]
    total: int
    page: int
    size: int


# ------------------------------------------------------------------------------
# Injeção de Dependências & Contexto de Autenticação/Multitenancy
# ------------------------------------------------------------------------------
# Mock das dependências de banco de dados e autenticação
def get_db():
    """Retorna uma sessão do SQLAlchemy."""
    pass

class CurrentUser:
    """Representa o usuário autenticado e seu tenant atual."""
    def __init__(self, user_id: int, tenant_id: int):
        self.user_id = user_id
        self.tenant_id = tenant_id

def get_current_user() -> CurrentUser:
    """Extrai o usuário do token JWT/Sessão."""
    pass


# ------------------------------------------------------------------------------
# Controller / Endpoint
# ------------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/customers", tags=["Customers"])


@router.get(
    "",
    response_model=PaginatedCustomersResponse,
    status_code=status.HTTP_200_OK,
    summary="Lista os clientes do tenant com suporte a filtro por nome",)
def list_customers(
    name: Optional[str] = Query(
        None,
        description="Filtro parcial do nome do cliente (case-insensitive)",
        min_length=1,),
    page: int = Query(1, ge=1, description="Número da página"),
    size: int = Query(20, ge=1, le=100, description="Quantidade de itens por página"),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),):
    """
    Lista os clientes cadastrados da empresa/tenant logada.
    Garante o isolamento multitenant aplicando o filtro obligatorio por `tenant_id`.
    """
    # Importação do model SQLAlchemy dentro da função para contexto do exemplo
    from models import Customer

    # 1. Base da query garantindo ISOLAMENTO MULTITENANT
    # Como todos os dados residem no mesmo BD, o tenant_id é OBRIGATÓRIO.
    query = select(Customer).where(Customer.tenant_id == current_user.tenant_id)

    # 2. Aplicação do filtro opcional por nome (busca parcial / case-insensitive)
    if name:
        query = query.where(Customer.name.ilike(f"%{name.strip()}%"))

    # 3. Contagem total de registros para metadados de paginação
    total = db.scalar(
        select(Customer.id)
        .where(Customer.tenant_id == current_user.tenant_id)
        .where(Customer.name.ilike(f"%{name.strip()}%") if name else True)
        .with_only_columns(Customer.id)
        .subquery()
        .select()
        .count()
    ) or 0

    # 4. Paginação (Offset e Limit)
    offset = (page - 1) * size
    results = db.scalars(query.offset(offset).limit(size)).all()

    return PaginatedCustomersResponse(
        items=results,
        total=total,
        page=page,
        size=size,
    )