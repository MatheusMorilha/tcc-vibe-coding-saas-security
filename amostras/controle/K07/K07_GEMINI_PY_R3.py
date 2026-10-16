import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from slowapi import Limiter
from slowapi.util import get_remote_address
from passlib.context import CryptContext
from jose import jwt
from sqlalchemy.orm import Session
from sqlalchemy import select, Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import declarative_base, relationship

# ---------------------------------------------------------
# Configurações de Ambiente e Segurança
# ---------------------------------------------------------
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

# Argon2 para hashing seguro contra ataques por força bruta em hardware paralelo
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# Hash sentinela para mitigar timing attacks quando o usuário não é encontrado
DUMMY_PASSWORD_HASH = pwd_context.hash("dummy_fallback_password")

# Rate Limiter contra ataques de força bruta e credential stuffing
limiter = Limiter(key_func=get_remote_address)

# ---------------------------------------------------------
# Modelos de Dados (SQLAlchemy ORM)
# ---------------------------------------------------------
Base = declarative_base()


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    subscription_status = Column(String(50), nullable=False, default="active")  # 'active', 'canceled', etc.
    subscription_expires_at = Column(DateTime(timezone=True), nullable=True)

    users = relationship("User", back_populates="tenant")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    tenant = relationship("Tenant", back_populates="users")


# ---------------------------------------------------------
# Schemas (Pydantic)
# ---------------------------------------------------------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "gestor@empresa.com",
                "password": "SenhaUltraSegura123!"
            }
        }
    }


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# ---------------------------------------------------------
# Funções Auxiliares de Criptografia e Sessão
# ---------------------------------------------------------
def create_session_token(user_id: int, tenant_id: int) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = now + expires_delta

    payload = {
        "sub": str(user_id),
        "tenant_id": tenant_id,  # Contexto multilocatário essencial
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": secrets.token_hex(16)  # Identificador único para suportar revogação/blacklisting
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token, int(expires_delta.total_seconds())


# ---------------------------------------------------------
# Dependência de Banco de Dados (Stub para injeção)
# ---------------------------------------------------------
def get_db():
    # Substituir pela sua engine/SessionLocal real
    db = Session()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------
# Rota de Autenticação
# ---------------------------------------------------------
auth_router = APIRouter(prefix="/api/v1/auth", tags=["Autenticação"])


@auth_router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Autentica o usuário e emite token com contexto de tenant",)
@limiter.limit("5/minute")# OWASP A04: Limite estrito de 5 tentativas por minuto por IP
def login(
    request: Request,
    credentials: LoginRequest,
    db: Session = Depends(get_db)):
    # OWASP A07: Erro genérico único para prevenir enumeração de contas
    invalid_credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas ou conta inacessível.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Busca parametrizada prevenindo SQL Injection (OWASP A03)
    stmt = (
        select(User)
        .join(Tenant)
        .where(User.email == credentials.email.lower().strip())
    )
    user = db.scalar(stmt)

    # 2. Mitigação de Timing Attack:
    # Se o usuário não existir, executa o hash contra a constante para balancear o tempo de resposta
    target_hash = user.hashed_password if user else DUMMY_PASSWORD_HASH
    is_password_valid = pwd_context.verify(credentials.password, target_hash)

    if not user or not is_password_valid:
        raise invalid_credentials_exception

    # 3. Verificações de Status do Usuário
    if not user.is_active:
        raise invalid_credentials_exception

    # 4. Verificação de Regras Multilocatárias (OWASP A01: Broken Access Control)
    tenant = user.tenant
    if not tenant or not tenant.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="O acesso para esta organização foi desativado.",
        )

    # 5. Validação do Plano de Assinatura
    now = datetime.now(timezone.utc)
    is_expired = tenant.subscription_expires_at and tenant.subscription_expires_at < now
    if tenant.subscription_status != "active" or is_expired:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="A assinatura da organização está inativa ou expirada.",
        )

    # 6. Emissão do Token de Sessão
    access_token, expires_in = create_session_token(
        user_id=user.id,
        tenant_id=user.tenant_id
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in
    )