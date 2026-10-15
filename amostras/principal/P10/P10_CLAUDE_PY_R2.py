# app/routes/users.py
from datetime import datetime, timezone
import re
import uuid

from argon2 import PasswordHasher
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

router = APIRouter(prefix="/users", tags=["users"])
ph = PasswordHasher()  # Argon2id


# ---------------------------------------------------------------- Modelos
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200))
    subscription_active: Mapped[bool] = mapped_column(default=True)
    max_users: Mapped[int] = mapped_column(Integer)  # limite do plano


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        # e-mail único dentro de cada empresa
        UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(150))
    email: Mapped[str] = mapped_column(String(254))  # sempre normalizado (minúsculo)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ---------------------------------------------------------------- Schemas
class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rejeita campos extras (ex.: tenant_id, is_admin)

    name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

    @field_validator("name")
    @classmethod
    def clean_name(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Nome inválido.")
        return v

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        if not (re.search(r"[a-z]", v) and re.search(r"[A-Z]", v) and re.search(r"\d", v)):
            raise ValueError("A senha deve conter letras maiúsculas, minúsculas e números.")
        return v


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    email: EmailStr
    created_at: datetime
    # password / password_hash e tenant_id nunca são expostos


# ---------------------------------------------------------------- Dependências
# Implementações reais ficam no módulo de infraestrutura/autenticação.
def get_db() -> Session:
    raise NotImplementedError


def get_current_user() -> User:
    """Valida o token (JWT/sessão) e devolve o usuário autenticado."""
    raise NotImplementedError


def require_tenant_admin(current: User = Depends(get_current_user)) -> User:
    if not current.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente.")
    return current


# ---------------------------------------------------------------- Rota
@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_tenant_admin),
):
    tenant_id = admin.tenant_id  # vem do contexto autenticado, nunca do corpo

    # Bloqueia a linha da empresa para evitar corrida no limite de usuários do plano
    tenant = db.execute(
        select(Tenant).where(Tenant.id == tenant_id).with_for_update()
    ).scalar_one()

    if not tenant.subscription_active:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")

    current_count = db.execute(
        select(func.count()).select_from(User).where(User.tenant_id == tenant_id)
    ).scalar_one()
    if current_count >= tenant.max_users:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Limite de usuários do plano atingido."
        )

    email = payload.email.strip().lower()

    exists = db.execute(
        select(User.id).where(User.tenant_id == tenant_id, User.email == email)
    ).first()
    if exists:
        raise HTTPException(status.HTTP_409_CONFLICT, "E-mail já cadastrado.")

    user = User(
        tenant_id=tenant_id,
        name=payload.name,
        email=email,
        password_hash=ph.hash(payload.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:  # corrida: outro request criou o mesmo e-mail
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "E-mail já cadastrado.")

    db.refresh(user)
    return user