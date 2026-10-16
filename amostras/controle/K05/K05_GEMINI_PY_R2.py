# models.py
import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    pass

class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    # Índice composto para acelerar buscas filtradas por locatário
    __table_args__ = (
        Index("idx_tenant_customer_name", "tenant_id", "name"),
    )

# schemas.py
import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

class CustomerResponse(BaseModel):
    id: uuid.UUID
    name: str
    email: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class PaginatedCustomersResponse(BaseModel):
    items: list[CustomerResponse]
    limit: int
    offset: int

# auth.py
import uuid
import os
import jwt
from fastapi import HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "chave_secreta_de_exemplo_producao_via_vault")
ALGORITHM = "HS256"

security = HTTPBearer()

class AuthenticatedUser(BaseModel):
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    subscription_active: bool

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> AuthenticatedUser:
    """Valida o token JWT e extrai o contexto do locatário (OWASP A01 & A07)."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        tenant_id: str = payload.get("tenant_id")
        user_id: str = payload.get("sub")
        is_active: bool = payload.get("subscription_active", False)

        if not tenant_id or not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido: credenciais de locatário ausentes."
            )

        # Garante que tenants suspensos/inadimplentes não acessem recursos
        if not is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acesso bloqueado: plano de assinatura inativo."
            )

        return AuthenticatedUser(
            user_id=uuid.UUID(user_id),
            tenant_id=uuid.UUID(tenant_id),
            subscription_active=is_active
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Não foi possível autenticar o usuário."
        )

# main.py
import re
from typing import Annotated
from fastapi import FastAPI, Depends, Query, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# Importações dos módulos estruturados
from models import Customer
from schemas import PaginatedCustomersResponse, CustomerResponse
from auth import AuthenticatedUser, get_current_user

app = FastAPI(title="SaaS Enterprise API")

def sanitize_like_input(text: str) -> str:
    """Escapa metacaracteres de LIKE para evitar DoS por Regex/Wildcard no banco."""
    return re.sub(r"([%_\\])", r"\\\1", text)

@app.get(
    "/api/v1/customers",
    response_model=PaginatedCustomersResponse,
    status_code=status.HTTP_200_OK,
    summary="Lista clientes da empresa autenticada")
async def list_customers(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    # Dependency Injection do banco de dados assíncrono (exemplo com AsyncSession)
    # db: Annotated[AsyncSession, Depends(get_db)],
    name: Annotated[
        str | None,
        Query(
            max_length=100,
            regex=r"^[\w\s\-\.]*$",
            description="Filtro parcial por nome do cliente.")
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=100, description="Quantidade máxima de registros por página.")
    ] = 20,
    offset: Annotated[
        int,
        Query(ge=0, description="Deslocamento para paginação.")
    ] = 0,):
    """
    Lista clientes com suporte a filtro por nome, garantindo isolamento multilocatário.
    """
    # 1. Construção segura da query utilizando ORM tipado (Prevenção de SQL Injection - OWASP A03)
    query = select(Customer).where(Customer.tenant_id == user.tenant_id)

    # 2. Aplicação de filtro com escape de caracteres coringa
    if name and name.strip():
        safe_name = sanitize_like_input(name.strip())
        # ilike mapeia para parâmetros preparados (prepared statements) com escape explícito
        query = query.where(Customer.name.ilike(f"%{safe_name}%", escape="\\"))

    # 3. Limites de paginação obrigatórios para evitar esgotamento de memória/recursos
    query = query.order_by(Customer.name.asc()).offset(offset).limit(limit)

    # Execução (exemplo ilustrativo de resultado):
    # result = await db.execute(query)
    # customers = result.scalars().all()
    customers: list[Customer] = []  # Substituído pelo retorno real do banco

    return PaginatedCustomersResponse(
        items=[CustomerResponse.model_validate(c) for c in customers],
        limit=limit,
        offset=offset
    )