"""
auth.py - Rota de autenticação de uma plataforma SaaS multilocatária.

Dependências:
    pip install fastapi uvicorn sqlalchemy psycopg[binary] argon2-cffi pyjwt "pydantic[email]"

Variáveis de ambiente:
    DATABASE_URL    ex.: postgresql+psycopg://user:pass@host/db
    JWT_SECRET      segredo longo e aleatório (>= 32 bytes). Nunca versionar.
"""

import os
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, create_engine, select
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "saas-gestao"
TOKEN_TTL = timedelta(minutes=30)

MAX_FAILED_ATTEMPTS = 5
LOCK_DURATION = timedelta(minutes=15)
ACTIVE_SUBSCRIPTION_STATUSES = {"active", "trialing"}

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False)

ph = PasswordHasher()  # Argon2id com parâmetros padrão seguros
# Hash fictício usado para igualar o tempo de resposta quando o e-mail não existe
_DUMMY_HASH = ph.hash("senha-fictícia-para-timing")


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    """Empresa cliente."""

    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # active | trialing | past_due | canceled
    subscription_status: Mapped[str] = mapped_column(String(20), default="trialing")

    users: Mapped[list["User"]] = relationship(back_populates="tenant")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    # E-mail único globalmente e sempre armazenado em minúsculas
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(30), default="member")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="users")


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)  # limita custo do hash


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # segundos


# --------------------------------------------------------------------------- #
# Dependências e helpers
# --------------------------------------------------------------------------- #
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _invalid_credentials() -> HTTPException:
    # Mensagem única: não revela se o e-mail existe, se a conta está bloqueada etc.
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _issue_token(user: User) -> tuple[str, int]:
    now = _now()
    payload = {
        "iss": JWT_ISSUER,
        "sub": str(user.id),
        "tid": str(user.tenant_id),  # tenant lido do token nas demais rotas
        "role": user.role,
        "jti": uuid.uuid4().hex,  # permite revogação/denylist
        "iat": now,
        "exp": now + TOKEN_TTL,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, int(TOKEN_TTL.total_seconds())


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    email = body.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))

    # 1) Usuário inexistente: executa um verify fictício para manter o tempo constante
    if user is None:
        try:
            ph.verify(_DUMMY_HASH, body.password)
        except (VerifyMismatchError, InvalidHashError):
            pass
        raise _invalid_credentials()

    # 2) Conta temporariamente bloqueada por excesso de tentativas
    if user.locked_until and user.locked_until > _now():
        try:
            ph.verify(_DUMMY_HASH, body.password)
        except (VerifyMismatchError, InvalidHashError):
            pass
        raise _invalid_credentials()

    # 3) Verificação da senha
    try:
        ph.verify(user.password_hash, body.password)
    except (VerifyMismatchError, InvalidHashError):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = _now() + LOCK_DURATION
            user.failed_attempts = 0
        db.commit()
        raise _invalid_credentials()

    # 4) Credenciais corretas: só agora informamos o estado da conta/assinatura
    if not user.is_active or not user.tenant.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Conta desativada.")

    if user.tenant.subscription_status not in ACTIVE_SUBSCRIPTION_STATUSES:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="Assinatura da empresa inativa. Contate o administrador.",
        )

    # 5) Sucesso: zera contadores, atualiza hash se os parâmetros evoluíram
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = _now()
    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(body.password)
    db.commit()

    token, expires_in = _issue_token(user)
    return TokenResponse(access_token=token, expires_in=expires_in)


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
app = FastAPI(title="SaaS Gestão Empresarial")
app.include_router(router)