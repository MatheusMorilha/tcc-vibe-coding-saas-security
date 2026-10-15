from datetime import datetime, timedelta, timezone
import hashlib
import secrets

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    create_engine,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from passlib.context import CryptContext


# ============================================================
# Configuração
# ============================================================

DATABASE_URL= "postgresql+psycopg://user:password@localhost/saas"

SESSION_TTL= timedelta(hours=8)

engine= create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

pwd_context= CryptContext(
    schemes=["argon2"],
    deprecated="auto",
)

app= FastAPI()


# ============================================================
# Modelos
# ============================================================

class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__= "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)

    # Exemplo simplificado:
    subscription_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )


class User(Base):
    __tablename__= "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"),
        nullable=False,
        index=True,
    )

    # Deve possuir UNIQUE globalmente se o login tiver
    # somente e-mail + senha.
    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        unique=True,
        index=True,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )


class SessionToken(Base):
    __tablename__= "session_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

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

    # Nunca armazenamos o token puro.
    token_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


# ============================================================
# Schemas
# ============================================================

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_at: datetime
    user_id: int
    tenant_id: int


# ============================================================
# Funções auxiliares
# ============================================================

def normalize_email(email: str)-> str:
    return email.strip().lower()


def hash_session_token(token: str)-> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session_token()-> tuple[str, str]:
    """
    Retorna:
      - token puro: enviado ao cliente
      - hash: armazenado no banco
    """
    token= secrets.token_urlsafe(48)
    token_hash= hash_session_token(token)

    return token, token_hash


# ============================================================
# Dependência do banco
# ============================================================

def get_db():
    with Session(engine) as db:
        yield db


# ============================================================
# Rota de autenticação
# ============================================================

@app.post(
    "/auth/login",
    response_model=LoginResponse,
)
def login(
    payload: LoginRequest,
    db: Session= Depends(get_db),
):
    email= normalize_email(payload.email)

    # O e-mail é único globalmente.
    user= db.scalar(
        select(User).where(User.email== email)
    )

    # Não revelar se o e-mail existe.
    if useris None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
        )

    # Sempre valide a senha através do hash.
    password_valid= pwd_context.verify(
        payload.password,
        user.password_hash,
    )

    if not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
        )

    # Usuário desativado.
    if not user.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuário desativado",
        )

    # Carrega explicitamente o tenant pertencente ao usuário.
    tenant= db.scalar(
        select(Tenant).where(
            Tenant.id== user.tenant_id
        )
    )

    if tenantis None:
        # Estado inconsistente da base.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Empresa do usuário não encontrada",
        )

    # Verifica o plano da empresa.
    if not tenant.subscription_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Assinatura da empresa inativa",
        )

    # Gera token criptograficamente aleatório.
    raw_token, token_hash= create_session_token()

    expires_at= (
        datetime.now(timezone.utc) + SESSION_TTL
    )

    session_token= SessionToken(
        user_id=user.id,
        tenant_id=tenant.id,
        token_hash=token_hash,
        expires_at=expires_at,
    )

    db.add(session_token)
    db.commit()

    return LoginResponse(
        access_token=raw_token,
        token_type="Bearer",
        expires_at=expires_at,
        user_id=user.id,
        tenant_id=tenant.id,
    )