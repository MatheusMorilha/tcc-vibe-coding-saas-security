"""
Rota de cadastro de usuário - plataforma SaaS multilocatária.

Dependências:
    pip install fastapi uvicorn "sqlalchemy>=2.0" "pydantic[email]>=2" argon2-cffi pyjwt

Variáveis de ambiente:
    DATABASE_URL  (ex.: postgresql+psycopg://user:pass@host/db)
    JWT_SECRET
"""
import os
import uuid
from datetime import datetime, timezone

import jwt
from argon2 import PasswordHasher
from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint,
    create_engine, func, select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, Session, mapped_column, sessionmaker,
)

# --------------------------------------------------------------------------- #
# Infraestrutura
# --------------------------------------------------------------------------- #
engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
password_hasher = PasswordHasher()  # Argon2id
bearer_scheme = HTTPBearer()
JWT_SECRET = os.environ["JWT_SECRET"]


def get_db():
    with SessionLocal() as db:
        yield db


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200))
    subscription_active: Mapped[bool] = mapped_column(Boolean, default=True)
    max_users: Mapped[int] = mapped_column(Integer)  # limite do plano


class User(Base):
    __tablename__ = "users"
    # E-mail é único POR empresa (e não globalmente).
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(320))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="member")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rejeita campos como tenant_id/role

    name: str = Field(min_length=2, max_length=200)
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
    tenant_id: uuid.UUID
    name: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime
    # password / password_hash NUNCA fazem parte da resposta


# --------------------------------------------------------------------------- #
# Autenticação / contexto do tenant
# --------------------------------------------------------------------------- #
class Principal(BaseModel):
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    role: str


def get_principal(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> Principal:
    """O tenant vem do token validado, nunca do corpo da requisição."""
    try:
        claims = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
        return Principal(
            user_id=claims["sub"], tenant_id=claims["tenant_id"], role=claims["role"]
        )
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciais inválidas.")


def require_admin(principal: Principal = Depends(get_principal)) -> Principal:
    if principal.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente.")
    return principal


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/users", tags=["users"])


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin: Principal = Depends(require_admin),
):
    # Bloqueia a linha do tenant para evitar que cadastros simultâneos
    # ultrapassem o limite de usuários do plano.
    tenant = db.execute(
        select(Tenant).where(Tenant.id == admin.tenant_id).with_for_update()
    ).scalar_one_or_none()

    if tenant is None or not tenant.subscription_active:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")

    active_users = db.execute(
        select(func.count()).select_from(User).where(
            User.tenant_id == tenant.id, User.is_active.is_(True)
        )
    ).scalar_one()
    if active_users >= tenant.max_users:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Limite de usuários do plano atingido."
        )

    user = User(
        tenant_id=tenant.id,  # sempre o tenant do solicitante
        name=payload.name,
        email=payload.email.lower(),
        password_hash=password_hasher.hash(payload.password),
        role="member",
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Já existe um usuário com este e-mail."
        )

    return user


app = FastAPI(title="SaaS Gestão Empresarial")
app.include_router(router)