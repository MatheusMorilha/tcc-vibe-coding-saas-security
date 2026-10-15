"""
auth_routes.py
Rotas: POST /auth/refresh  e  POST /auth/logout

Decisões de segurança:
- Access token (JWT, curta duração) carrega sub (user), tid (tenant) e sid (sessão).
- Refresh token é opaco, aleatório, e só o HASH (SHA-256) fica no banco.
- Rotação a cada renovação; reuso de token antigo => sessão inteira revogada.
- Toda consulta é filtrada por tenant_id (isolamento entre empresas na mesma base).
- Renovação revalida usuário ativo e assinatura ativa da empresa.
- Logout é idempotente e só afeta sessões do próprio usuário/tenant do token.
"""
import hashlib
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, String, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------
JWT_SECRET = os.environ["JWT_SECRET"]  # nunca versionar o segredo
JWT_ALGORITHM = "HS256"
ACCESS_TTL = timedelta(minutes=15)
REFRESH_TTL = timedelta(days=30)
ACTIVE_SUBSCRIPTIONS = {"active", "trialing"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Modelos (ajuste ao seu schema existente)
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    subscription_status: Mapped[str] = mapped_column(String(20))


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    refresh_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    previous_hash: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


def get_db():  # substitua pela sua dependência real de sessão do banco
    raise NotImplementedError


# --------------------------------------------------------------------------
# Utilitários de token
# --------------------------------------------------------------------------
def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def issue_access_token(user_id: str, tenant_id: str, session_id: str) -> str:
    now = utcnow()
    payload = {
        "sub": user_id,
        "tid": tenant_id,
        "sid": session_id,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ACCESS_TTL,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def unauthorized(detail: str = "Credenciais inválidas ou sessão expirada.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=512)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class LogoutRequest(BaseModel):
    all_devices: bool = False  # True => encerra todas as sessões do usuário


class LogoutResponse(BaseModel):
    success: bool
    detail: str
    revoked_sessions: int


# --------------------------------------------------------------------------
# Dependência de autenticação (usada no logout)
# --------------------------------------------------------------------------
bearer = HTTPBearer(auto_error=False)


def get_current_session(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> UserSession:
    if creds is None:
        raise unauthorized()
    try:
        claims = jwt.decode(
            creds.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "sub", "tid", "sid"]},
        )
    except jwt.PyJWTError:
        raise unauthorized()

    sess = db.scalar(
        select(UserSession).where(
            UserSession.id == claims["sid"],
            UserSession.tenant_id == claims["tid"],  # isolamento por empresa
            UserSession.user_id == claims["sub"],
        )
    )
    if sess is None or sess.revoked_at is not None:
        raise unauthorized()
    return sess


# --------------------------------------------------------------------------
# Rotas
# --------------------------------------------------------------------------
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/refresh", response_model=TokenResponse)
def refresh_session(body: RefreshRequest, db: Session = Depends(get_db)) -> TokenResponse:
    presented = hash_token(body.refresh_token)
    now = utcnow()

    sess = db.scalar(
        select(UserSession).where(UserSession.refresh_hash == presented).with_for_update()
    )

    if sess is None:
        # Reuso de refresh token já rotacionado => possível vazamento: derruba a sessão.
        reused = db.scalar(
            select(UserSession).where(UserSession.previous_hash == presented).with_for_update()
        )
        if reused is not None and reused.revoked_at is None:
            reused.revoked_at = now
            db.commit()
        raise unauthorized()

    if sess.revoked_at is not None or as_utc(sess.expires_at) <= now:
        raise unauthorized()

    # Revalida usuário e assinatura do tenant a cada renovação.
    row = db.execute(
        select(User.is_active, Tenant.subscription_status)
        .join(Tenant, Tenant.id == User.tenant_id)
        .where(User.id == sess.user_id, User.tenant_id == sess.tenant_id)
    ).first()

    if row is None or not row.is_active:
        sess.revoked_at = now
        db.commit()
        raise unauthorized()

    if row.subscription_status not in ACTIVE_SUBSCRIPTIONS:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="A assinatura da empresa não está ativa.",
        )

    # Rotação do refresh token.
    new_refresh = new_refresh_token()
    sess.previous_hash = sess.refresh_hash
    sess.refresh_hash = hash_token(new_refresh)
    sess.expires_at = now + REFRESH_TTL
    db.commit()

    return TokenResponse(
        access_token=issue_access_token(sess.user_id, sess.tenant_id, sess.id),
        refresh_token=new_refresh,
        expires_in=int(ACCESS_TTL.total_seconds()),
    )


@router.post("/logout", response_model=LogoutResponse)
def logout(
    body: LogoutRequest | None = None,
    current: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> LogoutResponse:
    now = utcnow()
    all_devices = bool(body and body.all_devices)

    stmt = update(UserSession).where(
        UserSession.tenant_id == current.tenant_id,
        UserSession.user_id == current.user_id,
        UserSession.revoked_at.is_(None),
    )
    if not all_devices:
        stmt = stmt.where(UserSession.id == current.id)

    result = db.execute(stmt.values(revoked_at=now))
    db.commit()

    return LogoutResponse(
        success=True,
        detail="Todas as sessões encerradas." if all_devices else "Sessão encerrada com sucesso.",
        revoked_sessions=result.rowcount,
    )