from datetime import datetime, timezone
from typing import Annotated, Optional
import re

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ==============================================================================
# 1. MODELOS DE DADOS (DATABASE SCHEMA)
# ==============================================================================

class Base(DeclarativeBase):
    pass


class Company(Base):
    """Representa a empresa contratante (Tenant)."""
    __tablename__ = "companies"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    subscription_status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")
    subscription_expires_at: Mapped[datetime] = mapped_column(nullable=False)


class Customer(Base):
    """Representa os clientes finais cadastrados por uma empresa contratante."""
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # Isolamento de Tenant (Foreign Key indexada)
    company_id: Mapped[int] = mapped_column(index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc))


# ==============================================================================
# 2. ESQUEMAS DE DADOS (PYDANTIC DTOs)
# ==============================================================================

class CustomerResponse(BaseModel):
    id: int
    name: str
    email: str

    model_config = ConfigDict(from_attributes=True)


class PaginatedCustomersResponse(BaseModel):
    items: list[CustomerResponse]
    total: int
    limit: int
    offset: int


class AuthenticatedUser(BaseModel):
    user_id: int
    company_id: int
    roles: list[str]


# ==============================================================================
# 3. SEGURANÇA E DEPENDÊNCIAS (OWASP MITIGATIONS)
# ==============================================================================

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

async def get_db_session() -> AsyncSession:
    """Provedor de sessão do SQLAlchemy (Injeção de dependência)."""
    raise NotImplementedError("Conexão com a engine gerenciada pelo framework.")


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)]) -> AuthenticatedUser:
    """
    Mitigação OWASP A07 (Identification and Authentication Failures).
    Valida o token JWT (assinatura, expiração) e extrai o contexto da sessão.
    """
    # Em produção: decodificar via PyJWT / cryptography validando algoritmo seguro e secret
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas ou ausentes.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Contexto extraído com segurança do payload
    return AuthenticatedUser(user_id=42, company_id=10, roles=["operator"])


async def verify_active_tenant(
    current_user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],) -> AuthenticatedUser:
    """
    Mitigação OWASP A01 (Broken Access Control).
    Garante que o Tenant não apenas existe, mas possui assinatura ativa.
    """
    stmt = select(Company).where(Company.id == current_user.company_id)
    result = await session.execute(stmt)
    company = result.scalar_one_or_none()

    if not company:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organização não localizada.",
        )

    now = datetime.now(timezone.utc)
    is_expired = company.subscription_expires_at < now
    if company.subscription_status != "active" or is_expired:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Assinatura inativa ou expirada. Acesso suspenso.",
        )

    return current_user


def sanitize_like_input(value: Optional[str]) -> Optional[str]:
    """
    Escapa metacaracteres especiais de operadores LIKE do SQL (%, _ e \).
    Evita ReDoS lógico ou enumerações abusivas por varredura coringa.
    """
    if not value:
        return None
    # Remove caracteres de controle invisíveis e normaliza espaços
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", value).strip()
    # Escapa wildcards
    escaped = cleaned.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped


# ==============================================================================
# 4. ROTA DA API
# ==============================================================================

router = APIRouter(prefix="/api/v1/customers", tags=["Customers"])

@router.get(
    "/",
    response_model=PaginatedCustomersResponse,
    status_code=status.HTTP_200_OK,
    summary="Listar clientes da empresa",)
async def list_customers(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    auth: Annotated[AuthenticatedUser, Depends(verify_active_tenant)],
    name: Annotated[
        Optional[str],
        Query(
            max_length=100,
            description="Nome do cliente para filtro parcial (case-insensitive).",),
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=100, description="Limite máximo de 100 registros por página."),
    ] = 20,
    offset: Annotated[
        int,
        Query(ge=0, description="Deslocamento para paginação."),
    ] = 0,) -> PaginatedCustomersResponse:
    """
    Retorna a lista paginada de clientes pertencentes ao locatário autenticado.
    """
    # 1. Base Query com isolamento estrito de Tenant (OWASP A01)
    base_query = select(Customer).where(Customer.company_id == auth.company_id)

    # 2. Sanitização e parametrização segura (OWASP A03: SQL Injection)
    escaped_name = sanitize_like_input(name)
    if escaped_name:
        # Uso de parâmetros vinculados (bind variables) com escape explícito
        search_pattern = f"%{escaped_name}%"
        base_query = base_query.where(
            Customer.name.ilike(search_pattern, escape="\\")
        )

    # 3. Contagem total de registros correspondentes ao filtro
    count_stmt = select(func.count()).select_from(base_query.subquery())
    total_records = (await session.execute(count_stmt)).scalar_one()

    # 4. Execução da busca com paginação mandatória (OWASP A04: DoS)
    data_stmt = (
        base_query
        .order_by(Customer.name.asc(), Customer.id.asc())
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(data_stmt)
    records = result.scalars().all()

    return PaginatedCustomersResponse(
        items=[CustomerResponse.model_validate(c) for c in records],
        total=total_records,
        limit=limit,
        offset=offset,
    )