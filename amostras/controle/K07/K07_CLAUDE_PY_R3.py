"""
Rota de autenticação para plataforma SaaS multilocatária.

Dependências (fixar versões e auditar com pip-audit / Dependabot):
    fastapi, uvicorn, sqlalchemy>=2.0, psycopg[binary], argon2-cffi, pydantic[email]

Variáveis de ambiente:
    DATABASE_URL   ex.: postgresql+psycopg://user:pass@host/db  (obrigatória)
    SESSION_TTL_MINUTES (padrão 60)
    ENABLE_DOCS    "1" apenas em desenvolvimento
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Annotated, Deque, Dict

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, create_engine, select, update,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, Session, mapped_column, sessionmaker,
)

# --------------------------------------------------------------------------
# Configuração (A05: sem segredos/valores sensíveis no código; falha se ausente)
# --------------------------------------------------------------------------
DATABASE_URL = os.environ["DATABASE_URL"]  # KeyError se não configurada
SESSION_TTL = timedelta(minutes=int(os.getenv("SESSION_TTL_MINUTES", "60")))
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
COOKIE_NAME = "__Host-session"  # prefixo __Host- exige Secure, Path=/ e sem Domain

logger = logging.getLogger("auth")

# --------------------------------------------------------------------------
# Banco de dados
# --------------------------------------------------------------------------
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    status: Mapped[str] = mapped_column(String(20))  # active | canceled | past_due
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    # E-mail único global (sempre armazenado em minúsculas)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    # Armazena apenas o HASH do token: vazamento da base não expõe sessões válidas
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ip: Mapped[str] = mapped_column(String(45))
    user_agent: Mapped[str] = mapped_column(String(256))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[Session, Depends(get_db)]

# --------------------------------------------------------------------------
# Criptografia (A02): Argon2id com parâmetros explícitos
# --------------------------------------------------------------------------
_ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)
# Hash "isca": garante tempo de resposta equivalente quando o e-mail não existe
# (mitiga enumeração de usuários por timing).
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(16))


def _verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def hash_session_token(token: str) -> str:
    """Use a mesma função ao validar a sessão em requisições futuras."""
    return hashlib.sha256(token.encode()).hexdigest()


# --------------------------------------------------------------------------
# Rate limiting (A04/A07). Em produção com várias instâncias, use Redis
# (ex.: redis + sliding window) ou o rate limit do API gateway/WAF.
# --------------------------------------------------------------------------
class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window_s: int) -> bool:
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] > window_s:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


limiter = SlidingWindowLimiter()

# --------------------------------------------------------------------------
# Schemas (A03: validação estrita de entrada)
# --------------------------------------------------------------------------
class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    email: EmailStr = Field(max_length=254)
    # Limite superior evita DoS por senhas gigantes no Argon2
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    user_id: int
    tenant_id: int
    expires_at: datetime


# --------------------------------------------------------------------------
# Auxiliares
# --------------------------------------------------------------------------
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _client_ip(request: Request) -> str:
    # Atrás de proxy/LB, configure uvicorn com --proxy-headers e
    # --forwarded-allow-ips restrito aos IPs confiáveis. Nunca confie em
    # X-Forwarded-For arbitrário (A04/A05).
    return request.client.host if request.client else "unknown"


def _email_fingerprint(email: str) -> str:
    # Evita registrar PII em claro nos logs (A09)
    return hashlib.sha256(email.encode()).hexdigest()[:12]


def _invalid_credentials() -> HTTPException:
    # Mensagem única para usuário inexistente, senha errada ou conta bloqueada
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas.",
    )


def _has_active_subscription(db: Session, tenant_id: int, now: datetime) -> bool:
    stmt = (
        select(Subscription.id)
        .where(
            Subscription.tenant_id == tenant_id,
            Subscription.status == "active",
            Subscription.expires_at > now,
        )
        .limit(1)
    )
    return db.scalar(stmt) is not None


def _register_failure(db: Session, user: User, now: datetime) -> None:
    # Incremento atômico no banco (evita race condition entre tentativas paralelas)
    db.execute(
        update(User)
        .where(User.id == user.id)
        .values(failed_attempts=User.failed_attempts + 1)
    )
    db.flush()
    db.refresh(user)
    if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
        db.execute(
            update(User)
            .where(User.id == user.id)
            .values(locked_until=now + LOCKOUT_DURATION, failed_attempts=0)
        )
        logger.warning(
            "auth.account_locked user_id=%s tenant_id=%s", user.id, user.tenant_id
        )
    db.commit()


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DbSession,
) -> LoginResponse:
    ip = _client_ip(request)
    email = payload.email.lower()
    fingerprint = _email_fingerprint(email)
    now = _utcnow()

    # 1) Rate limit por IP e por e-mail (força bruta / credential stuffing)
    if not (limiter.allow(f"ip:{ip}", 30, 60) and limiter.allow(f"email:{email}", 10, 60)):
        logger.warning("auth.rate_limited ip=%s email_fp=%s", ip, fingerprint)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas. Tente novamente mais tarde.",
            headers={"Retry-After": "60"},
        )

    # 2) Busca parametrizada via ORM (A03: sem concatenação de SQL)
    user = db.scalar(select(User).where(User.email == email))

    # 3) Verificação de senha SEMPRE executada (tempo constante p/ existente
    #    e inexistente), inclusive quando a conta está bloqueada.
    stored_hash = user.password_hash if user else _DUMMY_HASH
    password_ok = _verify_password(stored_hash, payload.password) and user is not None
    locked = bool(user and user.locked_until and user.locked_until > now)

    if user is None or locked or not password_ok:
        if user is not None and not locked:
            _register_failure(db, user, now)
        logger.info(
            "auth.login_failed ip=%s email_fp=%s locked=%s", ip, fingerprint, locked
        )
        raise _invalid_credentials()

    # 4) Credenciais válidas: agora é seguro revelar o motivo de recusa por
    #    estado da conta/assinatura (o requisitante provou ser o titular).
    tenant = db.get(Tenant, user.tenant_id)
    if not user.is_active or tenant is None or not tenant.is_active:
        logger.info("auth.denied_inactive user_id=%s tenant_id=%s", user.id, user.tenant_id)
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Conta desativada.")

    if not _has_active_subscription(db, user.tenant_id, now):
        logger.info("auth.denied_subscription user_id=%s tenant_id=%s", user.id, user.tenant_id)
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="A assinatura da empresa não está ativa.",
        )

    # 5) Atualiza hash se os parâmetros do Argon2 evoluíram
    if _ph.check_needs_rehash(user.password_hash):
        user.password_hash = _ph.hash(payload.password)

    user.failed_attempts = 0
    user.locked_until = None

    # 6) Emite token de sessão opaco, aleatório e criptograficamente seguro
    token = secrets.token_urlsafe(32)  # 256 bits de entropia
    expires_at = now + SESSION_TTL
    db.add(
        UserSession(
            user_id=user.id,
            tenant_id=user.tenant_id,  # isolamento: sessão sempre atrelada ao tenant
            token_hash=hash_session_token(token),
            created_at=now,
            expires_at=expires_at,
            ip=ip,
            user_agent=(request.headers.get("user-agent") or "")[:256],
        )
    )
    db.commit()

    # 7) Token entregue em cookie HttpOnly (inacessível a JS => mitiga XSS),
    #    Secure e SameSite=Strict (mitiga CSRF). Não vai no corpo da resposta.
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    logger.info("auth.login_success user_id=%s tenant_id=%s ip=%s", user.id, user.tenant_id, ip)

    return LoginResponse(user_id=user.id, tenant_id=user.tenant_id, expires_at=expires_at)


# --------------------------------------------------------------------------
# Aplicação (A05: cabeçalhos de segurança, docs desabilitadas em produção)
# --------------------------------------------------------------------------
def create_app() -> FastAPI:
    docs_enabled = os.getenv("ENABLE_DOCS") == "1"
    app = FastAPI(
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return resp

    app.include_router(router)
    return app


app = create_app()