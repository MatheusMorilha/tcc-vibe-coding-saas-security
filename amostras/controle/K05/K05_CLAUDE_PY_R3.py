"""
Rota: GET /api/v1/customers?name=<texto>&page=1&page_size=20

Plataforma SaaS multilocatária (base compartilhada).
Dependências: fastapi, sqlalchemy>=2.0, pydantic>=2, pyjwt[crypto]
"""
import logging
import os
import uuid
from datetime import datetime
from typing import Annotated, Optional

import jwt  # PyJWT
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict
from sqlalchemy import DateTime, ForeignKey, Index, String, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("api.customers")

# ---------------------------------------------------------------------------
# Configuração (A02/A05: segredos e parâmetros vêm do ambiente, sem defaults)
# ---------------------------------------------------------------------------
JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
JWT_ISSUER = os.environ["JWT_ISSUER"]
JWT_AUDIENCE = os.environ["JWT_AUDIENCE"]
JWT_ALGORITHMS = ["RS256"]  # algoritmo fixado: nunca aceitar "none" ou HS* com chave pública

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 20
ACTIVE_SUBSCRIPTION_STATUSES = {"active", "trialing"}
REQUIRED_PERMISSION = "customers:read"


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    subscription_status: Mapped[str] = mapped_column(String(20))


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    # Em produção, normalmente derivado de papéis (RBAC) em tabela própria.
    permissions: Mapped[str] = mapped_column(String(500), default="")

    def has_permission(self, perm: str) -> bool:
        return perm in self.permissions.split(",")


class Customer(Base):
    __tablename__ = "customers"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    email: Mapped[Optional[str]] = mapped_column(String(254))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    # Índice composto: toda consulta começa por tenant_id
    __table_args__ = (Index("ix_customers_tenant_name", "tenant_id", "name"),)


# ---------------------------------------------------------------------------
# Schemas de resposta (A01/A04: exposição mínima de dados, lista explícita)
# ---------------------------------------------------------------------------
class CustomerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    email: Optional[str] = None
    created_at: datetime


class CustomerPage(BaseModel):
    items: list[CustomerOut]
    page: int
    page_size: int
    total: int


# ---------------------------------------------------------------------------
# Sessão de banco (a ser substituída pela fábrica real da aplicação)
# ---------------------------------------------------------------------------
def get_db() -> Session:  # pragma: no cover
    raise NotImplementedError("Injete a fábrica de sessões da aplicação")


# ---------------------------------------------------------------------------
# Autenticação e autorização
# ---------------------------------------------------------------------------
bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorized() -> HTTPException:
    # Mensagem genérica: não revela o motivo da falha (A07)
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não autenticado",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    creds: Annotated[Optional[HTTPAuthorizationCredentials], Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    if creds is None:
        raise _unauthorized()
    try:
        claims = jwt.decode(
            creds.credentials,
            JWT_PUBLIC_KEY,
            algorithms=JWT_ALGORITHMS,
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
        user_id = uuid.UUID(claims["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise _unauthorized()

    # O estado do usuário é conferido na base (revogação, desativação, mudança
    # de tenant ou de permissões não dependem apenas do token).
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _unauthorized()
    return user


def require_customers_read(user: Annotated[User, Depends(get_current_user)]) -> User:
    if not user.has_permission(REQUIRED_PERMISSION):
        logger.warning("Acesso negado: permissão ausente user=%s tenant=%s", user.id, user.tenant_id)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso negado")
    return user


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------
def escape_like(value: str, escape_char: str = "\\") -> str:
    """Neutraliza curingas do LIKE (%, _) para que o filtro seja busca literal."""
    return (
        value.replace(escape_char, escape_char * 2)
        .replace("%", escape_char + "%")
        .replace("_", escape_char + "_")
    )


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1", tags=["customers"])


@router.get("/customers", response_model=CustomerPage)
def list_customers(
    response: Response,
    user: Annotated[User, Depends(require_customers_read)],
    db: Annotated[Session, Depends(get_db)],
    # A03: validação de entrada (tamanho e rejeição de caracteres de controle)
    name: Annotated[
        Optional[str],
        Query(min_length=1, max_length=100, pattern=r"^[^\x00-\x1f\x7f]+$",
              description="Filtro por nome (contém, sem diferenciar maiúsculas)"),
    ] = None,
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
) -> CustomerPage:
    # A01/A04: plano de assinatura ativo é pré-condição de uso
    tenant = db.get(Tenant, user.tenant_id)
    if tenant is None or tenant.subscription_status not in ACTIVE_SUBSCRIPTION_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Assinatura inativa",
        )

    # A01: o tenant vem SEMPRE do usuário autenticado, nunca da requisição.
    # Esse predicado é aplicado em qualquer cenário (com ou sem filtro).
    conditions = [Customer.tenant_id == user.tenant_id]

    if name:
        term = name.strip()
        if term:
            # A03: consulta parametrizada via ORM + curingas escapados
            conditions.append(Customer.name.ilike(f"%{escape_like(term)}%", escape="\\"))

    base = select(Customer).where(*conditions)

    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0

    rows = db.scalars(
        base.order_by(Customer.name, Customer.id)  # ordenação estável p/ paginação
        .limit(page_size)
        .offset((page - 1) * page_size)
    ).all()

    # A09: log útil para auditoria, sem PII nem texto livre do usuário (evita log injection)
    logger.info(
        "customers.list user=%s tenant=%s filtered=%s page=%d size=%d results=%d",
        user.id, user.tenant_id, bool(name), page, page_size, len(rows),
    )

    # A02/A05: dados de clientes não devem ser armazenados em cache
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"

    return CustomerPage(
        items=[CustomerOut.model_validate(r) for r in rows],
        page=page,
        page_size=page_size,
        total=total,
    )


# ---------------------------------------------------------------------------
# Aplicação (A05: sem docs/debug expostos em produção)
# ---------------------------------------------------------------------------
app = FastAPI(
    docs_url=None if os.getenv("APP_ENV") == "production" else "/docs",
    redoc_url=None,
    openapi_url=None if os.getenv("APP_ENV") == "production" else "/openapi.json",
)
app.include_router(router)