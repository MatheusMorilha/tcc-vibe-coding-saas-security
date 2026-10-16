"""
Rota de autenticação para plataforma SaaS multilocatária.

Dependências:
    pip install fastapi uvicorn sqlalchemy psycopg[binary] argon2-cffi pydantic[email]

Variáveis de ambiente:
    DATABASE_URL  ex.: postgresql+psycopg://user:senha@host:5432/saas
    SESSION_TTL_MINUTES (opcional, padrão 60)

Execução (atrás de proxy reverso com TLS):
    uvicorn app:app --proxy-headers --forwarded-allow-ips="IP_DO_PROXY"
"""
import hashlib
import logging
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

# --------------------------------------------------------------------------- #
# Configuração (A05: nada de segredos/credenciais hardcoded)
# --------------------------------------------------------------------------- #
DATABASE_URL = os.environ["DATABASE_URL"]  # falha explícita se ausente
SESSION_TTL = timedelta(minutes=int(os.getenv("SESSION_TTL_MINUTES", "60")))

MAX_FAILED_ATTEMPTS = 5                 # tentativas por conta antes do bloqueio
LOCKOUT_DURATION = timedelta(minutes=15)
IP_RATE_LIMIT = (20, 60)                # 20 requisições / 60 s por IP
ACTIVE_SUBSCRIPTIONS = {"active", "trialing"}

logger = logging.getLogger("auth")      # A09: log de eventos de segurança

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
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    subscription_status: Mapped[str] = mapped_column(String(20))  # active, trialing, past_due, canceled
    subscription_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    # Login recebe apenas e-mail + senha, portanto o e-mail precisa ser
    # globalmente único (armazenado sempre normalizado em minúsculas).
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    # A02: só o HASH do token é persistido; um vazamento da base não expõe sessões válidas.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))


# --------------------------------------------------------------------------- #
# Hash de senha (A02/A07): Argon2id, parâmetros atualizáveis via rehash
# --------------------------------------------------------------------------- #
ph = PasswordHasher()  # Argon2id por padrão
# Hash "isca": verificado quando o usuário não existe, para igualar o tempo de
# resposta e impedir enumeração de contas por timing.
_DUMMY_HASH = ph.hash(secrets.token_urlsafe(32))


def _verify_password(stored_hash: str, password: str) -> bool:
    try:
        return ph.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


# --------------------------------------------------------------------------- #
# Rate limit por IP (A04/A07). Em produção com várias instâncias, use Redis.
# --------------------------------------------------------------------------- #
class SlidingWindowLimiter:
    def __init__(self, max_calls: int, window_s: int):
        self.max_calls, self.window_s = max_calls, window_s
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window_s:
                q.popleft()
            if len(q) >= self.max_calls:
                return False
            q.append(now)
            return True


ip_limiter = SlidingWindowLimiter(*IP_RATE_LIMIT)


# --------------------------------------------------------------------------- #
# Schemas (A03: validação estrita de entrada)
# --------------------------------------------------------------------------- #
class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rejeita campos inesperados
    email: EmailStr = Field(max_length=254)
    # Limite superior evita DoS por senhas gigantes no Argon2.
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # segundos


# --------------------------------------------------------------------------- #
# Aplicação
# --------------------------------------------------------------------------- #
app = FastAPI(docs_url=None, redoc_url=None)  # A05: sem docs expostas em produção


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _invalid_credentials() -> HTTPException:
    # Mensagem única e genérica: não revela se o e-mail existe, está bloqueado ou inativo.
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas.",
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.post("/auth/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    # Respostas com token nunca devem ser armazenadas em cache.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    ip = request.client.host if request.client else "unknown"
    user_agent = (request.headers.get("user-agent") or "")[:255]

    # 1) Rate limit por IP
    if not ip_limiter.allow(ip):
        logger.warning("login_rate_limited ip=%s", ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas. Tente novamente mais tarde.",
            headers={"Retry-After": str(IP_RATE_LIMIT[1])},
        )

    now = _utcnow()
    email = payload.email.strip().lower()

    # 2) Busca parametrizada (ORM) -> sem SQL injection (A03).
    #    with_for_update serializa tentativas concorrentes na mesma conta,
    #    evitando corrida no contador de falhas.
    user = db.execute(
        select(User).where(User.email == email).with_for_update()
    ).scalar_one_or_none()

    # 3) Verificação SEMPRE executada (hash real ou isca): tempo constante.
    password_ok = _verify_password(user.password_hash if user else _DUMMY_HASH, payload.password)

    is_locked = bool(user and user.locked_until and user.locked_until > now)
    authenticated = bool(user and password_ok and user.is_active and not is_locked)

    if not authenticated:
        if user and not is_locked and user.is_active and not password_ok:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = now + LOCKOUT_DURATION
                user.failed_login_attempts = 0
                logger.warning("account_locked user_id=%s tenant_id=%s ip=%s",
                               user.id, user.tenant_id, ip)
            db.commit()
        else:
            db.rollback()
        logger.info("login_failed user_id=%s ip=%s", user.id if user else None, ip)
        raise _invalid_credentials()

    # 4) Credenciais válidas: valida o tenant e a assinatura (regra de negócio SaaS).
    tenant = db.get(Tenant, user.tenant_id)
    subscription_valid = bool(
        tenant
        and tenant.is_active
        and tenant.subscription_status in ACTIVE_SUBSCRIPTIONS
        and (tenant.subscription_expires_at is None or tenant.subscription_expires_at > now)
    )
    if not subscription_valid:
        db.rollback()
        logger.info("login_denied_subscription user_id=%s tenant_id=%s ip=%s",
                    user.id, user.tenant_id, ip)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso indisponível para esta conta. Contate o administrador.",
        )

    # 5) Atualiza hash se os parâmetros do Argon2 foram reforçados (A02).
    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(payload.password)

    # 6) Emite token de sessão opaco (256 bits de entropia, CSPRNG).
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    db.add(
        UserSession(
            user_id=user.id,
            tenant_id=user.tenant_id,  # toda checagem posterior deve filtrar por tenant_id
            token_hash=token_hash,
            created_at=now,
            expires_at=now + SESSION_TTL,
            ip_address=ip[:45],
            user_agent=user_agent,
        )
    )
    db.commit()

    logger.info("login_success user_id=%s tenant_id=%s ip=%s", user.id, user.tenant_id, ip)
    return LoginResponse(access_token=raw_token, expires_in=int(SESSION_TTL.total_seconds()))