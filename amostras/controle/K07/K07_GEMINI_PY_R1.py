import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, select
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import declarative_base, relationship

# ---------------------------------------------------------------------------
# Configurações de Segurança e Constantes
# OWASP A02: Chaves e segredos extraídos de variáveis de ambiente
# ---------------------------------------------------------------------------
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "ALTERAR_EM_PRODUCAO_PARA_CHAVE_ALTA_ENTROPIA_256_BITS")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Instância do hasher Argon2 (OWASP A02: Cryptographic Failures)
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

# Rate Limiter contra força bruta (OWASP A07: Identification & Auth Failures)
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/auth", tags=["Autenticação"])
Base = declarative_base()

# ---------------------------------------------------------------------------
# Modelos de Dados (Multi-Tenant com Isolamento Lógico)
# ---------------------------------------------------------------------------
class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    subscription_status = Column(String(50), default="active", nullable=False)  # active, past_due, canceled


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="member", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    failed_login_attempts = Column(String, default="0", nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("Tenant")


# ---------------------------------------------------------------------------
# Schemas Pydantic (Validação e Prevenção de Mass Assignment)
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


# ---------------------------------------------------------------------------
# Helpers de Criptografia e Sessão
# ---------------------------------------------------------------------------
# Hash dummy para mitigar User Enumeration e Timing Attacks (OWASP A07)
DUMMY_PASSWORD_HASH = ph.hash("senha_falsa_para_equalizar_tempo_de_resposta")


def create_session_token(user: User) -> str:
    """
    Gera token de sessão JWT assinado.
    Obrigatoriamente vincula tenant_id (OWASP A01: Broken Access Control).
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "jti": str(uuid.uuid4()),  # Identificador único para possibilitar revogação
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


# Mock de injeção de dependência do SQLAlchemy (substitua pela sua engine real)
async def get_db():
    raise NotImplementedError("Injetar AsyncSession real da infraestrutura")


# ---------------------------------------------------------------------------
# Rota de Autenticação
# ---------------------------------------------------------------------------
@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Autentica um usuário e emite um token de sessão com contexto do locatário",)
@limiter.limit("5/minute")# OWASP A07: Máximo de 5 tentativas por minuto por IP
async def login(
    request: Request,
    credentials: LoginRequest,
    db: AsyncSession = Depends(get_db),):
    # OWASP A07 / A09: Mensagem genérica para prevenir enumeração de contas
    invalid_credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas ou conta temporariamente indisponível.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Busca do usuário (OWASP A03: Query parametrizada via SQLAlchemy ORM)
    stmt = (
        select(User)
        .join(Tenant, User.tenant_id == Tenant.id)
        .where(User.email == credentials.email.lower().strip())
    )
    result = await db.execute(stmt)
    user: Optional[User] = result.scalars().first()

    # 2. Mitigação de Timing Attack: se o usuário não existe, computa hash dummy
    # Isso garante que o tempo de processamento seja idêntico para e-mails válidos e inválidos.
    target_hash = user.password_hash if user else DUMMY_PASSWORD_HASH

    try:
        password_valid = ph.verify(target_hash, credentials.password)
    except VerifyMismatchError:
        password_valid = False

    if not user or not password_valid:
        raise invalid_credentials_exception

    # 3. Verificações de Tenant e Status de Conta (OWASP A01: Broken Access Control)
    # Garante que um usuário inativo ou tenant suspenso não receba token de sessão
    tenant_active = user.tenant.is_active and user.tenant.subscription_status in ("active", "trial")
    if not user.is_active or not tenant_active:
        raise invalid_credentials_exception

    # 4. Atualização de rehash se os parâmetros de segurança do Argon2 mudaram
    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(credentials.password)

    # 5. Auditoria de acesso e emissão de sessão
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    token = create_session_token(user)

    return LoginResponse(
        access_token=token,
        token_type="Bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )