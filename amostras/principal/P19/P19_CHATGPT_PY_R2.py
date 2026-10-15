from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import String, Boolean, ForeignKey, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy import create_engine

from passlib.context import CryptContext
from jose import jwt


# ============================================================
# Configuração
# ============================================================

DATABASE_URL= "postgresql+psycopg://app:password@localhost/app"

JWT_SECRET= "substitua-por-um-segredo-forte"
JWT_ALGORITHM= "HS256"
SESSION_DURATION_MINUTES= 60

pwd_context= CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)

engine= create_engine(DATABASE_URL)


# ============================================================
# Modelos
# ============================================================

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
        String(255),
        nullable=False,
    )

    active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
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
    expires_in: int


# ============================================================
# Utilitários
# ============================================================

def get_db():
    with Session(engine) as db:
        yield db


def verify_password(
    plain_password: str,
    password_hash: str,
)-> bool:
    return pwd_context.verify(
        plain_password,
        password_hash,
    )


def create_session_token(user: User)-> str:
    now= datetime.now(timezone.utc)
    expires_at= now+ timedelta(
        minutes=SESSION_DURATION_MINUTES
    )

    payload= {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


# ============================================================
# API
# ============================================================

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

    # O tenant NÃO vem do cliente.
    # O tenant é obtido do próprio registro autenticado.
    stmt= select(User).where(
        User.email== email,
        User.active.is_(True),
    )

    user= db.scalar(stmt)

    # Não revelar se o e-mail existe.
    if useris None or not verify_password(
        credentials.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
        )

    token= create_session_token(user)

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        expires_in=SESSION_DURATION_MINUTES* 60,
    )