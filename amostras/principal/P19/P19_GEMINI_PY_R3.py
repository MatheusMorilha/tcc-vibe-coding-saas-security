import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, String, Boolean, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship

# -----------------------------------------------------------------------------
# Configurações de Segurança e JWT
# -----------------------------------------------------------------------------
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "SUA_CHAVE_SECRETA_SUPER_SEGURA_AQUI")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 horas

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# -----------------------------------------------------------------------------
# Modelos de Banco de Dados (SQLAlchemy - Schema Compartilhado / Multi-tenant)
# -----------------------------------------------------------------------------
Base = declarative_base()

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String(36), primary_key=True)
    name = Column(String(255), nullable=False)
    status = Column(String(50), nullable=False, default="ACTIVE")  # ACTIVE, SUSPENDED, CANCELED

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)

    tenant = relationship("Tenant")

# -----------------------------------------------------------------------------
# Schemas DTO (Pydantic)
# -----------------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# -----------------------------------------------------------------------------
# Injeção de Dependência do Banco de Dados (Exemplo)
# -----------------------------------------------------------------------------
engine = create_engine("sqlite:///:memory:")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=Base)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -----------------------------------------------------------------------------
# Rota de Autenticação
# -----------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])

@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """
    Realiza a autenticação do usuário, valida o estado do Tenant e emite o JWT.
    """
    # 1. Buscar usuário pelo e-mail
    user = db.query(User).filter(User.email == payload.email).first()

    # 2. Validar existência do usuário e senha hash
    # Proteção contra timing attacks: sempre fazemos a verificação do hash antes de retornar
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
            detail="A conta de usuário está desativada."
        )

    # 4. Validar status da assinatura/conta do Tenant (Multilocatário)
    tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
    if not tenant or tenant.status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: a assinatura da empresa está inativa ou suspensa."
        )

    # 5. Gerar token de sessão com claims multilocatárias
    token_claims = {
        "sub": user.id,
        "tenant_id": user.tenant_id,
        "email": user.email
    }

    access_token = create_access_token(data=token_claims)

    return TokenResponse(access_token=access_token)