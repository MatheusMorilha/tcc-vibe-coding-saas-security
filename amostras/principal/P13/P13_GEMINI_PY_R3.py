from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from sqlalchemy import select

# Presuma a existência dos módulos de banco de dados e autenticação da aplicação
from database import get_db
from models import Customer
from auth import get_current_user, UserPayload

router = APIRouter(prefix="/customers", tags=["Customers"])

# --- Schemas (Pydantic) ---
class CustomerResponse(BaseModel):
    id: int
    name: str
    email: str
    phone: Optional[str] = None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


# --- Endpoint ---
@router.get(
    "/",
    response_model=List[CustomerResponse],
    status_code=status.HTTP_200_OK,
    summary="Listar clientes da empresa",
    description="Retorna a lista de clientes pertencentes ao locatário autenticado, com suporte a busca por nome.")
def list_customers(
    name: Optional[str] = Query(
        None,
        description="Termo para filtragem parcial do nome do cliente (case-insensitive)"),
    skip: int = Query(0, ge=0, description="Número de registros a ignorar (paginação)"),
    limit: int = Query(20, ge=1, le=100, description="Quantidade máxima de registros a retornar"),
    db: Session = Depends(get_db),
    current_user: UserPayload = Depends(get_current_user)):
    """
    Lista os clientes cadastrados para o tenant do usuário logado.
    """
    # Construção da query base garantindo estritamente o isolamento de tenant
    query = select(Customer).where(Customer.tenant_id == current_user.tenant_id)

    # Aplicação do filtro por nome, caso fornecido
    if name:
        query = query.where(Customer.name.ilike(f"%{name}%"))

    # Aplicação de paginação e ordenação
    query = query.order_by(Customer.name.asc()).offset(skip).limit(limit)

    customers = db.scalars(query).all()
    return customers