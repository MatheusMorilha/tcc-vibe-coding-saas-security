"""
Rota de cadastro de usuário - plataforma SaaS multilocatária.

Dependências:
    pip install fastapi uvicorn sqlalchemy psycopg[binary] pydantic[email] \
                argon2-cffi pyjwt

Variáveis de ambiente obrigatórias:
    DATABASE_URL   ex.: postgresql+psycopg://app:senha@db:5432/saas
    JWT_SECRET     segredo forte (>= 32 bytes), nunca versionado
    JWT_ISSUER     ex.: https://auth.minhaplataforma.com
    JWT_AUDIENCE   ex.: saas-api
"""
from __future__ import annotations

import logging
import os
import re
import unicodedata
import uuid
from datetime import datetime, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError  # noqa: F401
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint,
    create_engine, func, select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

# --------------------------------------------------------------------------- #
# Configuração (A05: sem segredos hardcoded; falha rápida se ausente)
# --------------------------------------------------------------------------- #
def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Variável de ambiente obrigatória ausente: {name}")
    return value


DATABASE_URL = _require_env("DATABASE_URL")
JWT_SECRET = _require_env("JWT_SECRET")
JWT_ISSUER = _require_env("JWT_ISSUER")
JWT_AUDIENCE = _require_env("JWT_AUDIENCE")
if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET deve ter ao menos 32 caracteres")

logger = logging.getLogger("app.users")

# --------------------------------------------------------------------------- #
# Banco de dados (A03: ORM com consultas parametrizadas, sem SQL concatenado)
# --------------------------------------------------------------------------- #
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(160))


class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    status: Mapped[str] = mapped_column(String(20))  # 'active', 'past_due', ...
    max_users: Mapped[int] = mapped_column(Integer)


class User(Base):
    __tablename__ = "users"
    # Unicidade do e-mail POR empresa; a restrição no banco elimina condições de corrida.
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(254))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="member")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Hash de senha (A02: Argon2id, salt único gerado pela biblioteca)
# --------------------------------------------------------------------------- #
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)

# --------------------------------------------------------------------------- #
# Schemas (A03/A04: validação estrita; sem mass assignment)
# --------------------------------------------------------------------------- #
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class UserCreate(BaseModel):
    # extra="forbid": rejeita campos como tenant_id, role, is_active enviados pelo cliente.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=2, max_length=120)
    email: EmailStr = Field(max_length=254)
    password: str = Field(min_length=12, max_length=128, repr=False)

    @field_validator("name")
    @classmethod
    def _clean_name(cls, v: str) -> str:
        v = unicodedata.normalize("NFC", v)
        if _CONTROL_CHARS.search(v):
            raise ValueError("Nome contém caracteres inválidos")
        return v

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return v.lower()

    @model_validator(mode="after")
    def _password_policy(self):
        # Política alinhada ao NIST 800-63B: comprimento > complexidade arbitrária.
        pwd = self.password
        if pwd.lower() == self.email.lower() or self.email.split("@")[0].lower() in pwd.lower():
            raise ValueError("A senha não pode conter o e-mail")
        if len(set(pwd)) < 5:
            raise ValueError("Senha muito previsível")
        return self


class UserOut(BaseModel):
    # Resposta explícita: nunca expõe password_hash nem dados internos.
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    email: EmailStr
    role: str
    created_at: datetime


# --------------------------------------------------------------------------- #
# Autenticação / autorização (A01, A07)
# --------------------------------------------------------------------------- #
def get_current_admin(request: Request, db: Session = Depends(get_db)) -> User:
    auth = request.headers.get("Authorization", "")
    scheme, _, token = auth.partition(" ")
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Credenciais inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if scheme.lower() != "bearer" or not token:
        raise unauthorized
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],  # algoritmo fixo: evita "alg=none"/confusão de algoritmo
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
        user_id = uuid.UUID(claims["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise unauthorized

    # Estado e papel vêm do banco, não do token (tokens podem estar defasados).
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise unauthorized
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente")
    return user


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> User:
    # Isolamento multilocatário: o tenant vem SEMPRE do administrador autenticado.
    tenant_id = admin.tenant_id

    # Trava a linha do tenant para serializar cadastros concorrentes e
    # impedir estouro do limite de usuários do plano (A04: falha de regra de negócio).
    tenant = db.execute(
        select(Tenant).where(Tenant.id == tenant_id).with_for_update()
    ).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente")

    subscription = db.execute(
        select(Subscription).where(
            Subscription.tenant_id == tenant_id, Subscription.status == "active"
        )
    ).scalars().first()
    if subscription is None:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa")

    current_users = db.scalar(
        select(func.count()).select_from(User).where(User.tenant_id == tenant_id)
    )
    if current_users >= subscription.max_users:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Limite de usuários do plano atingido")

    user = User(
        tenant_id=tenant_id,
        name=payload.name,
        email=payload.email,
        password_hash=_hasher.hash(payload.password),
        role="member",  # privilégio mínimo; elevação é uma operação separada e auditada
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Seguro revelar o conflito aqui: o chamador é admin do próprio tenant.
        raise HTTPException(status.HTTP_409_CONFLICT, "E-mail já cadastrado nesta empresa")
    db.refresh(user)

    # A09: log de auditoria sem dados sensíveis (sem senha, sem hash, sem e-mail em claro).
    logger.info(
        "user_created",
        extra={
            "event": "user_created",
            "tenant_id": str(tenant_id),
            "actor_id": str(admin.id),
            "user_id": str(user.id),
            "ip": request.client.host if request.client else None,
            "ts": datetime.now(timezone.utc).isoformat(),
        },
    )
    return user


# --------------------------------------------------------------------------- #
# Aplicação (A05: docs desativadas, headers de segurança, erros genéricos)
# --------------------------------------------------------------------------- #
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):
    # Nunca vaza stack trace ou detalhes internos ao cliente.
    logger.exception("unhandled_error")
    return JSONResponse(status_code=500, content={"detail": "Erro interno"})