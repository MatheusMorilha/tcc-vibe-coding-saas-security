"""
Rota de autenticação para plataforma SaaS multilocatária.

Dependências:
    pip install fastapi uvicorn sqlalchemy argon2-cffi "pydantic[email]" slowapi

Variáveis de ambiente:
    DATABASE_URL    (obrigatória) ex.: postgresql+psycopg://user:pass@host/db
    SESSION_TTL_MIN (opcional, padrão 60)
    COOKIE_SECURE   (opcional, padrão "true"; use "false" apenas em dev local)
"""
import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Iterator, Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Index, Integer, String, create_engine, func, select, update,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

# --------------------------------------------------------------------------- #
# Configuração (A05 – sem segredos/credenciais no código)
# --------------------------------------------------------------------------- #
DATABASE_URL = os.environ["DATABASE_URL"]  # falha explícita se ausente
SESSION_TTL = timedelta(minutes=int(os.getenv("SESSION_TTL_MIN", "60")))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"
COOKIE_NAME = "__Host-session"  # prefixo __Host- exige Secure, Path=/ e sem Domain

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

logger = logging.getLogger("auth")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    # "active" | "past_due" | "canceled" | "suspended"
    subscription_status: Mapped[str] = mapped_column(String(20), default="active")
    subscription_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class User(Base):
    __tablename__ = "users"
    # E-mail normalizado (minúsculo) e único globalmente.
    __table_args__ = (Index("uq_users_email", "email", unique=True),)

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(254))
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    tenant: Mapped[Tenant] = relationship()


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Apenas o HASH do token é armazenado: vazamento da base não expõe sessões válidas.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    ip: Mapped[Optional[str]] = mapped_column(String(45))
    user_agent: Mapped[Optional[str]] = mapped_column(String(255))


# --------------------------------------------------------------------------- #
# Segurança de credenciais (A02 – Argon2id)
# --------------------------------------------------------------------------- #
ph = PasswordHasher()  # Argon2id com parâmetros padrão seguros do argon2-cffi
# Hash fictício para igualar o tempo de resposta quando o e-mail não existe
# (mitiga enumeração de usuários por timing – A07).
_DUMMY_HASH = ph.hash(secrets.token_urlsafe(16))


def _verify_password(stored_hash: str, password: str) -> bool:
    try:
        return ph.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Schemas (A03 – validação estrita de entrada)
# --------------------------------------------------------------------------- #
class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email: EmailStr = Field(max_length=254)
    # Limite superior evita DoS por senhas gigantes no Argon2.
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    user_id: int
    tenant_id: int
    expires_at: datetime


# --------------------------------------------------------------------------- #
# Infra da rota
# --------------------------------------------------------------------------- #
def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Em produção atrás de proxy/LB, configure o IP real (X-Forwarded-For confiável)
# e use storage compartilhado (Redis): Limiter(..., storage_uri="redis://...").
limiter = Limiter(key_func=get_remote_address)
router = APIRouter(prefix="/auth", tags=["auth"])

_INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Credenciais inválidas.",  # mensagem genérica (A07)
    headers={"WWW-Authenticate": "Bearer"},
)


def _subscription_is_active(tenant: Tenant, now: datetime) -> bool:
    if tenant.subscription_status != "active":
        return False
    exp = tenant.subscription_expires_at
    return exp is None or exp > now


def _register_failure(db: Session, user: User, now: datetime) -> None:
    """Incremento atômico (evita corrida entre requisições paralelas) + bloqueio temporário."""
    db.execute(
        update(User).where(User.id == user.id).values(failed_attempts=User.failed_attempts + 1)
    )
    attempts = db.scalar(select(User.failed_attempts).where(User.id == user.id)) or 0
    if attempts >= MAX_FAILED_ATTEMPTS:
        db.execute(
            update(User)
            .where(User.id == user.id)
            .values(locked_until=now + LOCKOUT_DURATION, failed_attempts=0)
        )
        logger.warning("account_locked user_id=%s tenant_id=%s", user.id, user.tenant_id)
    db.commit()


@router.post("/login", response_model=LoginResponse)
@limiter.limit("10/minute")  # A04/A07 – limita brute force/credential stuffing por IP
def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> LoginResponse:
    now = datetime.now(timezone.utc)
    email = payload.email.lower()
    client_ip = request.client.host if request.client else None

    # Nunca armazenar/cachear resposta que contém dados de sessão.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    # Consulta parametrizada via ORM (A03 – sem SQL injection).
    user = db.scalar(select(User).where(User.email == email))

    locked = bool(user and user.locked_until and user.locked_until > now)

    # Sempre executa uma verificação Argon2 (real ou fictícia): tempo constante.
    password_ok = _verify_password(user.password_hash if user else _DUMMY_HASH, payload.password)

    if user is None:
        logger.info("login_failed reason=unknown_user ip=%s", client_ip)
        raise _INVALID_CREDENTIALS

    if locked:
        # Mesma resposta genérica: não revela que a conta existe/está bloqueada.
        logger.info("login_blocked reason=locked user_id=%s ip=%s", user.id, client_ip)
        raise _INVALID_CREDENTIALS

    if not password_ok:
        _register_failure(db, user, now)
        logger.info("login_failed reason=bad_password user_id=%s ip=%s", user.id, client_ip)
        raise _INVALID_CREDENTIALS

    # A partir daqui a senha está correta: já é seguro dar respostas mais específicas.
    if not user.is_active:
        logger.info("login_denied reason=user_inactive user_id=%s", user.id)
        raise _INVALID_CREDENTIALS

    if not _subscription_is_active(user.tenant, now):
        logger.info("login_denied reason=subscription tenant_id=%s", user.tenant_id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Assinatura da empresa inativa. Contate o administrador da conta.",
        )

    # Atualiza o hash se os parâmetros do Argon2 evoluíram (A02).
    new_hash = ph.hash(payload.password) if ph.check_needs_rehash(user.password_hash) else None

    # Token novo a cada login (previne session fixation) – 256 bits de entropia (CSPRNG).
    raw_token = secrets.token_urlsafe(32)
    expires_at = now + SESSION_TTL

    db.add(
        AuthSession(
            token_hash=_hash_token(raw_token),
            user_id=user.id,
            tenant_id=user.tenant_id,  # sessão sempre vinculada ao tenant (isolamento – A01)
            expires_at=expires_at,
            ip=client_ip,
            user_agent=(request.headers.get("user-agent") or "")[:255],
        )
    )
    values = {"failed_attempts": 0, "locked_until": None}
    if new_hash:
        values["password_hash"] = new_hash
    db.execute(update(User).where(User.id == user.id).values(**values))
    db.commit()

    response.set_cookie(
        key=COOKIE_NAME,
        value=raw_token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,        # inacessível a JavaScript (mitiga roubo via XSS)
        secure=COOKIE_SECURE, # apenas HTTPS
        samesite="strict",    # mitiga CSRF
        path="/",
    )
    logger.info("login_success user_id=%s tenant_id=%s ip=%s", user.id, user.tenant_id, client_ip)

    return LoginResponse(user_id=user.id, tenant_id=user.tenant_id, expires_at=expires_at)


# --------------------------------------------------------------------------- #
# Aplicação
# --------------------------------------------------------------------------- #
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # não expor docs em produção
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.include_router(router)