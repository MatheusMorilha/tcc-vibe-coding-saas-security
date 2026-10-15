# app/routes/users.py
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from argon2 import PasswordHasher
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


# ----------------------------------------------------------------------------
# Modelos
# ----------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255))
    subscription_status: Mapped[str] = mapped_column(String(20), default="active")
    max_users: Mapped[int] = mapped_column(Integer)  # limite definido pelo plano


class User(Base):
    __tablename__ = "users"
    # E-mail único dentro de cada empresa (troque por unique global se preferir
    # que o e-mail identifique o usuário em toda a plataforma).
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(320))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="member")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


# ----------------------------------------------------------------------------
# Schemas
# ----------------------------------------------------------------------------
class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rejeita campos extras (ex.: tenant_id, role)

    name: str = Field(min_length=2, max_length=255)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

    @field_validator("name")
    @classmethod
    def strip_name(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Nome inválido.")
        return v


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime
    # password / password_hash e tenant_id nunca são expostos


# ----------------------------------------------------------------------------
# Dependências (a serem integradas à sua infraestrutura)
# ----------------------------------------------------------------------------
@dataclass
class AuthContext:
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    role: str


def get_db() -> Session:
    """Fornece a sessão do SQLAlchemy (implemente conforme seu setup)."""
    raise NotImplementedError


def get_current_admin() -> AuthContext:
    """Valida o token (JWT/sessão), retorna o contexto autenticado e
    exige perfil de administrador. Implemente na sua camada de auth."""
    raise NotImplementedError


# ----------------------------------------------------------------------------
# Rota
# ----------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/users", tags=["users"])
hasher = PasswordHasher()  # Argon2id


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin: AuthContext = Depends(get_current_admin),
) -> User:
    # Bloqueia a linha da empresa para evitar que cadastros simultâneos
    # ultrapassem o limite de usuários do plano.
    tenant = db.execute(
        select(Tenant).where(Tenant.id == admin.tenant_id).with_for_update()
    ).scalar_one_or_none()

    if tenant is None or tenant.subscription_status != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Assinatura inativa.")

    active_users = db.scalar(
        select(func.count(User.id)).where(
            User.tenant_id == tenant.id, User.is_active.is_(True)
        )
    )
    if active_users >= tenant.max_users:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            "Limite de usuários do plano atingido.",
        )

    user = User(
        tenant_id=tenant.id,  # sempre vem do contexto autenticado
        name=payload.name,
        email=payload.email.lower(),  # normaliza para evitar duplicidade por caixa
        password_hash=hasher.hash(payload.password),
        role="member",  # perfil nunca é definido pelo cliente
    )
    db.add(user)

    try:
        db.commit()  # a constraint única garante a unicidade mesmo sob concorrência
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "E-mail já cadastrado.")

    db.refresh(user)
    return user