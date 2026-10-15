"""
auth.py - Rota de login para plataforma SaaS multilocatária.

Dependências:
    pip install fastapi uvicorn sqlalchemy argon2-cffi "pydantic[email]"
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
SESSION_TTL = timedelta(hours=8)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

ph = PasswordHasher()  # Argon2id com parâmetros padrão seguros
# Hash fictício: usado para igualar o tempo de resposta quando o e-mail não existe
_DUMMY_HASH = ph.hash("senha-fictia-para-timing-constante")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Modelos (todas as empresas na mesma base -> tenant_id em tudo)
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    subscription_status: Mapped[str] = mapped_column(String(20), default="active")
    subscription_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    # Premissa: e-mail único globalmente (a rota recebe só e-mail e senha).
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


# ---------------------------------------------------------------------------
# Dependência de sessão de banco (ajuste para o seu projeto)
# ---------------------------------------------------------------------------
def get_db() -> Session:  # pragma: no cover
    raise NotImplementedError("Injete sua SessionLocal aqui")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _hash_token(token: str) -> str:
    # SHA-256 basta: o token tem 256 bits de entropia (não é senha de humano)
    return hashlib.sha256(token.encode()).hexdigest()


def _subscription_valid(tenant: Tenant) -> bool:
    if not tenant.is_active or tenant.subscription_status != "active":
        return False
    ends = tenant.subscription_ends_at
    return ends is None or ends > utcnow()


INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="E-mail ou senha inválidos.",
    headers={"WWW-Authenticate": "Bearer"},
)

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------
@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    email = payload.email.strip().lower()
    now = utcnow()

    user = db.scalar(select(User).where(User.email == email))

    # 1) Usuário inexistente: gasta o mesmo tempo de CPU e responde genericamente
    if user is None:
        try:
            ph.verify(_DUMMY_HASH, payload.password)
        except VerificationError:
            pass
        raise INVALID_CREDENTIALS

    # 2) Conta bloqueada temporariamente (mensagem genérica; não revela o bloqueio)
    if user.locked_until and user.locked_until > now:
        raise INVALID_CREDENTIALS

    # 3) Verificação da senha
    try:
        ph.verify(user.password_hash, payload.password)
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = now + LOCKOUT_DURATION
            user.failed_attempts = 0
        db.commit()
        raise INVALID_CREDENTIALS

    # 4) Credenciais corretas: só agora checamos usuário/empresa/assinatura
    #    (evita vazar informações sobre contas para quem não sabe a senha)
    tenant = db.get(Tenant, user.tenant_id)
    if not user.is_active or tenant is None or not tenant.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Acesso desativado.")
    if not _subscription_valid(tenant):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "A assinatura da empresa está inativa. Contate o administrador.",
        )

    # 5) Rehash transparente se os parâmetros do Argon2 evoluíram
    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(payload.password)

    # 6) Reseta contadores e emite a sessão
    user.failed_attempts = 0
    user.locked_until = None

    token = secrets.token_urlsafe(32)  # 256 bits, gerado por CSPRNG
    expires_at = now + SESSION_TTL
    db.add(
        UserSession(
            token_hash=_hash_token(token),  # nunca armazene o token em claro
            user_id=user.id,
            tenant_id=user.tenant_id,       # escopo do tenant fixado na sessão
            created_at=now,
            expires_at=expires_at,
            ip=request.client.host if request.client else None,
            user_agent=(request.headers.get("user-agent") or "")[:255],
        )
    )
    db.commit()

    # Evita cache do token por proxies/navegadores
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return LoginResponse(access_token=token, expires_at=expires_at)


# ---------------------------------------------------------------------------
# Exemplo de dependência para rotas protegidas (valida token e fixa o tenant)
# ---------------------------------------------------------------------------
def get_current_session(request: Request, db: Session = Depends(get_db)) -> UserSession:
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise INVALID_CREDENTIALS

    sess = db.scalar(
        select(UserSession).where(
            UserSession.token_hash == _hash_token(token),
            UserSession.revoked.is_(False),
            UserSession.expires_at > utcnow(),
        )
    )
    if sess is None:
        raise INVALID_CREDENTIALS
    return sess  # use sess.tenant_id em TODA query de negócio