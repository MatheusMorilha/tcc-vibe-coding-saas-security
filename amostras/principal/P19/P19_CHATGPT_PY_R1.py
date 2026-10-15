from datetime import datetime, timedelta, timezone
from typing import Generator

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import Boolean, ForeignKey, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


# -----------------------------------------------------------------------------
# Configuração
# -----------------------------------------------------------------------------

DATABASE_URL= "postgresql+psycopg://app:password@localhost/app"

JWT_SECRET= "substitua-por-um-segredo-longo-e-aleatorio"
JWT_ALGORITHM= "HS256"
SESSION_DURATION_MINUTES= 60

password_hasher= PasswordHasher()

engine= create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal= sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


# -----------------------------------------------------------------------------
# Banco de dados
# -----------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__= "tenants"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))


class User(Base):
    __tablename__= "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"),
        index=True,
        nullable=False,
    )
    email: Mapped[str] = mapped_column(
        String(320),
        index=True,
        nullable=False,
    )
    password_hash: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )
    active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )


# -----------------------------------------------------------------------------
# Schemas
# -----------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str


# -----------------------------------------------------------------------------
# Dependências
# -----------------------------------------------------------------------------

def get_db()-> Generator[Session, None, None]:
    db= SessionLocal()

    try:
        yield db
    finally:
        db.close()


# -----------------------------------------------------------------------------
# JWT
# -----------------------------------------------------------------------------

def create_session_token(user: User)-> str:
    now= datetime.now(timezone.utc)
    expires_at= now+ timedelta(minutes=SESSION_DURATION_MINUTES)

    payload= {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "iat": now,
        "exp": expires_at,
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


# -----------------------------------------------------------------------------
# API
# -----------------------------------------------------------------------------

app= FastAPI()


@app.post(
    "/auth/login",
    response_model=LoginResponse,
)
def login(
    credentials: LoginRequest,
    db: Session= Depends(get_db),
):
    email= credentials.email.strip().lower()

    # O usuário é identificado pelo e-mail.
    # O tenant_id é obtido do próprio registro do usuário.
    stmt= select(User).where(
        User.email== email,
        User.active.is_(True),
    )

    user= db.scalar(stmt)

    # Não revelar se o e-mail existe ou não.
    if useris None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
        )

    try:
        password_hasher.verify(
            user.password_hash,
            credentials.password,
        )
    except (VerifyMismatchError, InvalidHash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
        )

    # Opcional: atualizar automaticamente o hash caso os parâmetros
    # do Argon2 tenham sido alterados desde a criação do usuário.
    if password_hasher.check_needs_rehash(user.password_hash):
        user.password_hash= password_hasher.hash(credentials.password)
        db.commit()

    token= create_session_token(user)

    return LoginResponse(
        access_token=token,
        token_type="bearer",
    )