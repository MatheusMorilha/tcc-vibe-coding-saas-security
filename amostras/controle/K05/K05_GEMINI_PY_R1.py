from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.orm import Session
from sqlalchemy import select, and_

# Importações hipotéticas do seu núcleo de segurança/banco de dados
from app.database import get_db
from app.models import Customer
from app.auth import get_current_active_user, UserContext

router = APIRouter(prefix="/customers", tags=["Customers"])

# ==========================================
# SCHEMAS (Pydantic V2)
# ==========================================
class CustomerResponse(BaseModel):
    id: str = Field(..., description="ID único do cliente")
    name: str = Field(..., description="Nome do cliente")
    email: str = Field(..., description="E-mail de contato")
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# ENDPOINT
# ==========================================
@router.get(
    "",
    response_model=List[CustomerResponse],
    status_code=status.HTTP_200_OK,
    summary="Lista clientes da empresa autenticada")
def list_customers(
    # OWASP A03: Sanitize e limite os dados de entrada de parâmetros de busca
    name: Optional[str] = Query(
        None,
        min_length=1,
        max_length=100,
        description="Filtro parcial pelo nome do cliente"),
    limit: int = Query(20, ge=1, le=100, description="Limite para paginação"),
    offset: int = Query(0, ge=0, description="Offset para paginação"),
    current_user: UserContext = Depends(get_current_active_user),
    db: Session = Depends(get_db)):
    """
    Lista os clientes cadastrados para a empresa do usuário autenticado.
    Permite busca textual por nome de forma segura.
    """

    # OWASP A01: Garantir estritamente o isolamento de Tenant (Multitenancy Check)
    if not current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: contexto de tenant não identificado."
        )

    # Construção da query base com filtro mandatório de Tenant ID
    # OWASP A03: Utilização de ORM/Parameterized Queries contra SQL Injection
    query = select(Customer).where(Customer.tenant_id == current_user.tenant_id)

    # Aplicação do filtro por nome de forma segura
    if name:
        # Sanitização e escape de caracteres coringa SQL (% e _) no input do usuário
        sanitized_name = name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.where(Customer.name.ilike(f"%{sanitized_name}%"))

    # OWASP A04: Paginação obrigatória para evitar negação de serviço (DoS/Resource Exhaustion)
    query = query.offset(offset).limit(limit)

    results = db.scalars(query).all()
    return results