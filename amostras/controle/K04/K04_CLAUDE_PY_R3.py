"""
Rota de cadastro de usuário - plataforma SaaS multilocatária.

Dependências:
    pip install fastapi "pydantic[email]" sqlalchemy argon2-cffi

Premissas de arquitetura:
  * O tenant (empresa) NUNCA vem do corpo da requisição. Ele é derivado da
    identidade autenticada de quem está cadastrando (A01 - Broken Access Control).
  * Apenas usuários autenticados com a permissão "users:create" podem cadastrar.
  * Rate limiting (ex.: 10 req/min por IP/usuário) deve ser aplicado no
    API gateway / middleware (slowapi + Redis) - A04/A07.
  * A API deve ser servida somente via HTTPS (TLS terminado no gateway) - A02.
"""
from __future__ import annotations

import logging
import re
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterator

from argon2 import PasswordHasher
from argon2.low_level import Type
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("app.users")

# ---------------------------------------------------------------------------
# Modelos (base compartilhada, isolamento lógico por tenant_id)
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(160))
    subscription_active: Mapped[bool] = mapped_column(Boolean, default=True)
    max_users: Mapped[int] = mapped_column(Integer)  # limite do plano


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        # Unicidade de e-mail dentro do tenant; garantida pelo banco
        # (evita condição de corrida do tipo "verifica e depois insere").
        UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(254))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="member")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


# ---------------------------------------------------------------------------
# Segurança: hashing de senha (A02 - Cryptographic Failures)
# ---------------------------------------------------------------------------

# Argon2id com parâmetros acima do mínimo recomendado pela OWASP
# (m=19 MiB, t=2, p=1). Ajuste conforme o hardware de produção.
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # KiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

# Lista mínima de exemplo; em produção use a lista completa de senhas
# vazadas (ex.: API k-anonymity do HaveIBeenPwned ou arquivo local).
_SENHAS_COMUNS = frozenset(
    {"123456789012", "password1234", "senha1234567", "qwertyuiop12", "administrador"}
)

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# ---------------------------------------------------------------------------
# Schemas (A03 - Injection / A04 - Insecure Design: validação na entrada)
# ---------------------------------------------------------------------------


class UserCreate(BaseModel):
    # extra="forbid": rejeita campos inesperados (tenant_id, role, is_active...),
    # evitando mass assignment / escalonamento de privilégio.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=2, max_length=120)
    email: EmailStr = Field(max_length=254)
    # Política baseada no NIST 800-63B: comprimento > regras de composição.
    password: str = Field(min_length=12, max_length=128, repr=False)

    @field_validator("name")
    @classmethod
    def _valida_nome(cls, v: str) -> str:
        v = unicodedata.normalize("NFKC", v)
        if _CONTROL_CHARS.search(v):
            raise ValueError("Nome contém caracteres inválidos.")
        if any(c in v for c in "<>"):  # defesa em profundidade contra XSS armazenado
            raise ValueError("Nome contém caracteres inválidos.")
        return v

    @field_validator("email")
    @classmethod
    def _normaliza_email(cls, v: str) -> str:
        return v.lower()

    @model_validator(mode="after")
    def _valida_senha(self) -> "UserCreate":
        pwd = self.password
        if pwd.lower() in _SENHAS_COMUNS or len(set(pwd)) < 5:
            raise ValueError("Senha muito comum ou previsível.")
        local = self.email.split("@", 1)[0]
        if len(local) >= 4 and local in pwd.lower():
            raise ValueError("A senha não pode conter o e-mail.")
        return self


class UserOut(BaseModel):
    """Resposta explícita (allowlist): jamais expõe password_hash (A02/A04)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Autenticação / autorização (A01, A07)
# Implementação concreta fica na camada de auth (JWT/OIDC, sessão etc.).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    permissions: frozenset[str] = field(default_factory=frozenset)


def get_current_principal() -> Principal:  # pragma: no cover
    """Substituir pela validação real do token (assinatura, exp, aud, iss)."""
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Não autenticado.")


def require_permission(permission: str) -> Callable[..., Principal]:
    def _dep(principal: Principal = Depends(get_current_principal)) -> Principal:
        if permission not in principal.permissions:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Acesso negado.")
        return principal

    return _dep


def get_db() -> Iterator[Session]:  # pragma: no cover
    """Sessão SQLAlchemy por requisição (engine configurado fora deste módulo)."""
    from app.database import SessionLocal  # noqa: WPS433

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.post(
    "",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastra um usuário no tenant do solicitante",
)
def create_user(
    payload: UserCreate,
    response: Response,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("users:create")),
) -> User:
    # `def` (síncrono): o FastAPI executa em threadpool, então o hashing
    # Argon2 (CPU/memória intensivo) não bloqueia o event loop.
    response.headers["Cache-Control"] = "no-store"

    # O hash é calculado ANTES de abrir a seção crítica para não segurar
    # o lock da linha do tenant durante uma operação cara.
    password_hash = _hasher.hash(payload.password)

    # Trava a linha do tenant para serializar cadastros concorrentes e
    # impedir que o limite de usuários do plano seja ultrapassado.
    tenant = db.execute(
        select(Tenant).where(Tenant.id == principal.tenant_id).with_for_update()
    ).scalar_one_or_none()

    if tenant is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Acesso negado.")
    if not tenant.subscription_active:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa."
        )

    active_users = db.scalar(
        select(func.count())
        .select_from(User)
        .where(User.tenant_id == tenant.id, User.is_active.is_(True))
    )
    if active_users >= tenant.max_users:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Limite de usuários do plano atingido.",
        )

    user = User(
        tenant_id=tenant.id,       # sempre do contexto autenticado
        name=payload.name,
        email=payload.email,
        password_hash=password_hash,
        role="member",             # menor privilégio; papéis elevados via fluxo próprio
        is_active=True,
    )
    db.add(user)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Violação da unique (tenant_id, email). Mensagem sem detalhes de banco (A05).
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Não foi possível cadastrar com os dados informados.",
        ) from None
    except Exception:
        db.rollback()
        logger.exception("Falha ao persistir usuário")  # sem dados sensíveis
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "Erro interno."
        ) from None

    db.refresh(user)

    # Log de auditoria (A09): IDs apenas; nunca senha, hash ou e-mail completo.
    logger.info(
        "user_created",
        extra={
            "event": "user_created",
            "tenant_id": str(tenant.id),
            "actor_id": str(principal.user_id),
            "new_user_id": str(user.id),
        },
    )
    return user