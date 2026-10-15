import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Enum
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class TenantStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CANCELED = "canceled"

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    status = Column(Enum(TenantStatus), default=TenantStatus.ACTIVE, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    users = relationship("User", back_populates="tenant")

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    email = Column(String, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    tenant = relationship("Tenant", back_populates="users")

import os
from datetime import datetime, timedelta, timezone
import jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

# Configurações de segurança
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "sua_chave_secreta_muito_segura")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 horas

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)

    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"iat": now, "exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

# Schemas de Entrada e Saída (Pydantic)
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# Dependência do banco de dados (exemplo simplificado)
def get_db():
    # Retorna uma sessão do SQLAlchemy
    pass

app = FastAPI(title="SaaS Auth API")

@app.post(
    "/api/v1/auth/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Autentica um usuário de uma empresa cliente e emite o token JWT")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    # 1. Buscar usuário pelo e-mail
    user = db.query(User).filter(User.email == payload.email).first()

    # 2. Validar credenciais do usuário
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Validar se a conta do usuário está ativa
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuário inativo. Entre em contato com o administrador da sua empresa."
        )

    # 4. Validar o status da empresa cliente (Tenant) e seu plano de assinatura
    tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
    if not tenant or tenant.status != TenantStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A assinatura da empresa está inativa ou suspensa."
        )

    # 5. Gerar o token com os claims essenciais de multilocatário
    token_data = {
        "sub": user.id,
        "tenant_id": user.tenant_id,
        "email": user.email
    }

    access_token = create_access_token(data=token_data)

    return TokenResponse(access_token=access_token)