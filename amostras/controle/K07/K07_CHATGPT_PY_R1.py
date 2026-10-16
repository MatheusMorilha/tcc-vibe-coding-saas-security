"""
POST /api/v1/auth/login

Dependências:
    pip install fastapi sqlalchemy argon2-cffi uvicorn

Observações:
- PostgreSQL é recomendado em produção.
- password_hash contém um hash Argon2id completo.
- sessions armazena somente o hash do token de sessão.
- O token em texto puro é entregue apenas ao cliente.
- Em produção, SECRET/DB URL devem vir de um secret manager/variáveis
  de ambiente, nunca do código-fonte.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Generator

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, String, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

SESSION_TTL = timedelta(hours=8)

# Parâmetros apropriados para começar; devem ser calibrados em infraestrutura
# real para manter a verificação abaixo de aproximadamente 1 segundo.
password_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,  # 19 MiB
    parallelism=1,
)


# ---------------------------------------------------------------------------
# Modelos SQLAlchemy
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(primary_key=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"),
        nullable=False,
        index=True,
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        index=True,
    )

    password_hash: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )

    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )


class SessionToken(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Nunca armazenamos o token de sessão em texto puro.
    token_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"),
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


# ---------------------------------------------------------------------------
# Schemas HTTP
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_email(email: str) -> str:
    """
    Normalização mínima e determinística.

    A política de equivalência de e-mails deve ser consistente também no
    cadastro e no banco. Não se deve aplicar regras arbitrárias como
    remover pontos ou '+' sem que isso seja uma política explícita.
    """
    return email.strip().casefold()


def hash_session_token(token: str) -> str:
    """
    SHA-256 é adequado aqui porque o token já possui alta entropia aleatória.

    Diferentemente de senha, não estamos tentando proteger um segredo
    humano de baixa entropia.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_session_token() -> str:
    """
    32 bytes aleatórios => 256 bits de entropia.
    """
    return secrets.token_urlsafe(32)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def get_db() -> Generator[Session, None, None]:
    """
    Substituir pela SessionFactory da aplicação.

    Exemplo real:
        with Session(engine) as session:
            yield session
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def check_login_rate_limit(request: Request) -> None:
    """
    Ponto de integração para Redis/API Gateway/WAF.

    Em produção, o rate limit deve considerar pelo menos:
      - IP;
      - combinação IP + identificador;
      - eventualmente tenant.

    NÃO implementar um contador somente em memória do processo:
    isso não funciona corretamente com múltiplas instâncias.
    """
    return


def register_failed_login(request: Request, email: str) -> None:
    """
    Registrar tentativa falha no sistema de rate limiting/auditoria.

    Não registrar a senha nem o token.
    """
    return


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

app = FastAPI()


@app.post(
    "/api/v1/auth/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> LoginResponse:

    check_login_rate_limit(request)

    email = normalize_email(payload.email)

    # -----------------------------------------------------------------------
    # 1. Busca o usuário.
    #
    # Não aceitamos tenant_id vindo do cliente para determinar a identidade.
    # O relacionamento User -> Tenant define o tenant autenticado.
    # -----------------------------------------------------------------------

    user = db.scalar(
        select(User)
        .where(User.email == email)
    )

    # Mensagem genérica para não revelar se o e-mail existe.
    invalid_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if user is None:
        register_failed_login(request, email)
        raise invalid_credentials

    # -----------------------------------------------------------------------
    # 2. Verificação do tenant.
    # -----------------------------------------------------------------------

    tenant = db.scalar(
        select(Tenant)
        .where(Tenant.id == user.tenant_id)
    )

    if tenant is None or not tenant.active or not user.active:
        register_failed_login(request, email)
        raise invalid_credentials

    # -----------------------------------------------------------------------
    # 3. Verificação do password hash.
    #
    # O banco contém Argon2id, nunca a senha original.
    # -----------------------------------------------------------------------

    if not verify_password(
        payload.password,
        user.password_hash,
    ):
        register_failed_login(request, email)
        raise invalid_credentials

    # -----------------------------------------------------------------------
    # 4. Upgrade transparente do hash quando os parâmetros forem alterados.
    # -----------------------------------------------------------------------

    if password_hasher.check_needs_rehash(user.password_hash):
        user.password_hash = password_hasher.hash(payload.password)

    # -----------------------------------------------------------------------
    # 5. Criar nova sessão após autenticação.
    #
    # O identificador não é reutilizado e não é enviado na URL.
    # -----------------------------------------------------------------------

    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)

    now = datetime.now(timezone.utc)
    expires_at = now + SESSION_TTL

    session_token = SessionToken(
        token_hash=token_hash,
        user_id=user.id,
        tenant_id=user.tenant_id,
        created_at=now,
        expires_at=expires_at,
    )

    db.add(session_token)
    db.commit()

    # -----------------------------------------------------------------------
    # 6. O token em texto puro sai daqui somente na resposta.
    # -----------------------------------------------------------------------

    return LoginResponse(
        access_token=raw_token,
        token_type="Bearer",
        expires_in=int(SESSION_TTL.total_seconds()),
    )
