import os
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, select
from sqlalchemy.orm import declarative_base, relationship, Session

# ---------------------------------------------------------
# Configurações e Variáveis de Ambiente
# ---------------------------------------------------------
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "SUA_CHAVE_SECRETA_LONGA_E_ALEATORIA")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

# ---------------------------------------------------------
# Modelos de Banco de Dados (SQLAlchemy)
# ---------------------------------------------------------
Base = declarative_base()

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    subscription_plan = Column(String(50), default="standard", nullable=False)

    users = relationship("User", back_populates="tenant")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="member", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    tenant = relationship("Tenant", back_populates="users")

# ---------------------------------------------------------
# Schemas de Entrada e Saída (Pydantic v2)
# ---------------------------------------------------------
class LoginRequest(BaseModel):
    email: EmailStr
    # Limita o comprimento para evitar ataques de DoS por hash de strings gigantes
    password: str = Field(..., min_length=8, max_length=128)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

# ---------------------------------------------------------
# Utilitários de Segurança
# ---------------------------------------------------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> tuple[str, int]:
    to_encode = data.copy()
    expire_delta = expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire_at = datetime.now(timezone.utc) + expire_delta

    to_encode.update({
        "exp": expire_at,
        "iat": datetime.now(timezone.utc),
    })

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, int(expire_delta.total_seconds())

# Injeção de dependência fictícia para a sessão do banco
def get_db():
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
    summary="Autentica usuário e emite token com contexto multi-tenant")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    generic_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Busca usuário por e-mail com query parametrizada (OWASP A03 - Anti-Injection)
    stmt = (
        select(User)
        .join(Tenant)
        .where(User.email == payload.email)
    )
    user = db.execute(stmt).scalar_one_or_none()

    # 2. Validação segura de existência e senha
    # OWASP A07: Resposta uniforme para evitar enumeração de contas
    if not user:
        # Executa hash fictício para mitigar timing attacks caso o usuário não exista
        pwd_context.dummy_verify()
        raise generic_error

    if not verify_password(payload.password, user.hashed_password):
        raise generic_error

    # 3. Validação do ciclo de vida da conta e da organização (OWASP A01)
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso bloqueado. Conta de usuário inativa."
        )

    if not user.tenant.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso bloqueado. Assinatura da empresa suspensa ou inativa."
        )

    # 4. Geração do token contendo as claims multilocatárias
    token_claims = {
        "sub": str(user.id),
        "tenant_id": user.tenant_id,
        "role": user.role,
        "plan": user.tenant.subscription_plan,
    }

    access_token, expires_in = create_access_token(data=token_claims)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in
    )