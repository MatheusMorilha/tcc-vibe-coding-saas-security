"""
GET /api/v1/customers?name=<texto>&page=1&page_size=20

Dependências: fastapi, sqlalchemy>=2.0, pydantic>=2, pyjwt, psycopg[binary]
Variáveis de ambiente obrigatórias: DATABASE_URL, JWT_PUBLIC_KEY, JWT_ISSUER, JWT_AUDIENCE
"""
import logging
import os
import uuid
from datetime import datetime
from typing import Annotated, Optional

import jwt  # PyJWT
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import DateTime, ForeignKey, String, Boolean, Uuid, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

logger = logging.getLogger("api.customers")

# ---------------------------------------------------------------------------
# Configuração (A02/A05: segredos e configs fora do código, falha rápida)
# ---------------------------------------------------------------------------
DATABASE_URL = os.environ["DATABASE_URL"]
JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
JWT_ISSUER = os.environ["JWT_ISSUER"]
JWT_AUDIENCE = os.environ["JWT_AUDIENCE"]
JWT_ALGORITHMS = ["RS256"]  # A02/A07: algoritmo fixo, nunca aceitar "none" ou HS* com chave pública

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    subscription_status: Mapped[str] = mapped_column(String(20))  # active | past_due | canceled


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    permissions: Mapped[str] = mapped_column(String(500), default="")  # ex.: "customers:read,customers:write"


class Customer(Base):
    __tablename__ = "customers"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), index=True)
    email: Mapped[Optional[str]] = mapped_column(String(254))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Campos sensíveis (documento, dados bancários, etc.) existem no banco,
    # mas NÃO são expostos no schema de saída abaixo.


# ---------------------------------------------------------------------------
# Schemas (A01/A04: allowlist explícita de campos expostos)
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
# Dependências: sessão, autenticação, autorização
# ---------------------------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _unauthorized() -> HTTPException:
    # Mensagem genérica: não revela se o token expirou, se o usuário existe etc.
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não autenticado.",
        headers={"WWW-Authenticate": "Bearer"},
    )


class AuthContext(BaseModel):
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    permissions: frozenset[str]


def get_auth_context(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    """A07: valida o JWT (assinatura, exp, iss, aud) e confirma o usuário no banco.

    O tenant vem SEMPRE do registro do usuário no banco, nunca de parâmetro da
    requisição nem de header controlado pelo cliente.
    """
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise _unauthorized()

    try:
        claims = jwt.decode(
            token,
            JWT_PUBLIC_KEY,
            algorithms=JWT_ALGORITHMS,
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
        user_id = uuid.UUID(claims["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise _unauthorized()

    # Revalida no banco: usuário ativo e assinatura do tenant vigente
    row = db.execute(
        select(User, Tenant.subscription_status)
        .join(Tenant, Tenant.id == User.tenant_id)
        .where(User.id == user_id)
    ).first()
    if row is None or not row.User.is_active:
        raise _unauthorized()

    user, subscription_status = row
    if subscription_status != "active":
        # A04: regra de negócio do plano aplicada no servidor
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail="Assinatura inativa.")

    perms = frozenset(p.strip() for p in user.permissions.split(",") if p.strip())
    return AuthContext(user_id=user.id, tenant_id=user.tenant_id, permissions=perms)


def require_permission(permission: str):
    def checker(ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if permission not in ctx.permissions:  # A01: deny by default
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso negado.")
        return ctx

    return checker


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------
def escape_like(value: str) -> str:
    """Neutraliza curingas do LIKE (%, _) e a própria barra, evitando que o
    usuário force varreduras amplas ou padrões inesperados."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1", tags=["customers"])

NameParam = Annotated[
    Optional[str],
    Query(
        min_length=2,
        max_length=100,
        # Letras (unicode), dígitos, espaço e pontuação comum em nomes de empresas
        pattern=r"^[\w\s.,'&()\-]+$",
        description="Filtro por nome (busca parcial, sem diferenciar maiúsculas).",
    ),
]


@router.get("/customers", response_model=CustomerPage)
def list_customers(
    response: Response,
    name: NameParam = None,
    page: Annotated[int, Query(ge=1, le=10_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,  # A04: teto de paginação (anti-DoS/scraping)
    ctx: AuthContext = Depends(require_permission("customers:read")),
    db: Session = Depends(get_db),
):
    # A01: o filtro de tenant é obrigatório e vem do contexto autenticado
    conditions = [Customer.tenant_id == ctx.tenant_id]

    if name:
        # A03: ORM + parâmetros vinculados (sem concatenação de SQL) + escape de curingas
        conditions.append(Customer.name.ilike(f"%{escape_like(name.strip())}%", escape="\\"))

    total = db.scalar(select(func.count()).select_from(Customer).where(*conditions)) or 0

    items = db.scalars(
        select(Customer)
        .where(*conditions)
        .order_by(Customer.name, Customer.id)  # ordenação determinística para paginação estável
        .limit(page_size)
        .offset((page - 1) * page_size)
    ).all()

    # A09: log de auditoria sem PII (não registra o termo buscado, só metadados)
    logger.info(
        "customers_listed tenant=%s user=%s filtered=%s page=%d size=%d returned=%d",
        ctx.tenant_id, ctx.user_id, bool(name), page, page_size, len(items),
    )

    # Dados de clientes não devem ser cacheados por proxies/navegadores
    response.headers["Cache-Control"] = "no-store"

    return CustomerPage(
        items=[CustomerOut.model_validate(c) for c in items],
        page=page,
        page_size=page_size,
        total=total,
    )


# ---------------------------------------------------------------------------
# App: headers de segurança e tratamento genérico de erros
# ---------------------------------------------------------------------------
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # A05: sem docs expostas em produção
app.include_router(router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return resp


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # A05/A09: loga o detalhe internamente, devolve mensagem genérica (sem stack trace)
    error_id = uuid.uuid4().hex
    logger.exception("unhandled_error id=%s path=%s", error_id, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Erro interno.", "error_id": error_id})