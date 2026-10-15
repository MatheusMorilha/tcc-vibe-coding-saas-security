"""
auth_routes.py
Rotas de renovação de sessão (/auth/refresh) e encerramento de sessão (/auth/logout)
para plataforma SaaS multilocatária com base compartilhada.

Decisões de segurança:
- Access token (JWT) de vida curta, carregando tenant (tid), usuário (sub) e sessão (sid).
- Refresh token opaco, aleatório, armazenado apenas como hash SHA-256.
- Rotação a cada renovação + detecção de reuso (token antigo reapresentado => sessão revogada).
- Rotação atômica (UPDATE condicional) para evitar corrida entre requisições concorrentes.
- Toda consulta de usuário/sessão filtra por tenant_id (isolamento entre empresas).
- Renovação revalida usuário ativo e assinatura do tenant ativa.
- Logout revoga a sessão no servidor; o access token deixa de valer imediatamente,
  pois a dependência de autenticação consulta a sessão a cada requisição.
- Mensagens de erro genéricas para não vazar informação.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
JWT_SECRET = os.environ["JWT_SECRET"]  # nunca versionar; falha cedo se ausente
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "saas-gestao-api"
JWT_AUDIENCE = "saas-gestao-clients"
ACCESS_TOKEN_TTL = timedelta(minutes=15)

router = APIRouter(prefix="/auth", tags=["auth"])
bearer_scheme = HTTPBearer(auto_error=False)


# --------------------------------------------------------------------------- #
# Modelos (ajuste ao seu schema existente)
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    subscription_status: Mapped[str] = mapped_column(String(20))  # active | past_due | canceled
    subscription_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class UserSession(Base):
    __tablename__ = "user_sessions"
    __table_args__ = (
        Index("ix_sessions_current_hash", "current_refresh_hash", unique=True),
        Index("ix_sessions_previous_hash", "previous_refresh_hash"),
        Index("ix_sessions_tenant_user", "tenant_id", "user_id"),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    current_refresh_hash: Mapped[str] = mapped_column(String(64))
    previous_refresh_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))  # expiração absoluta
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------- #
# Dependência de banco (substitua pela sua)
# --------------------------------------------------------------------------- #
async def get_db() -> AsyncSession:  # pragma: no cover
    """Retorna uma AsyncSession. Importe a sua implementação real aqui."""
    raise NotImplementedError


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=512)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str  # novo token (rotação); o anterior deixa de valer
    token_type: str = "bearer"
    expires_in: int


class LogoutResponse(BaseModel):
    success: bool
    detail: str


# --------------------------------------------------------------------------- #
# Utilitários
# --------------------------------------------------------------------------- #
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(*, user_id: uuid.UUID, tenant_id: uuid.UUID, session_id: uuid.UUID) -> str:
    now = utcnow()
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": str(user_id),
        "tid": str(tenant_id),
        "sid": str(session_id),
        "typ": "access",
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _unauthorized(detail: str = "Credenciais inválidas ou sessão expirada.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _revoke_session(db: AsyncSession, session_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
    await db.execute(
        update(UserSession)
        .where(
            UserSession.id == session_id,
            UserSession.tenant_id == tenant_id,
            UserSession.revoked_at.is_(None),
        )
        .values(revoked_at=utcnow())
    )
    await db.commit()


def _subscription_is_valid(tenant: Tenant, now: datetime) -> bool:
    if not tenant.is_active or tenant.subscription_status != "active":
        return False
    return tenant.subscription_ends_at is None or tenant.subscription_ends_at > now


# --------------------------------------------------------------------------- #
# Dependência de autenticação (usada pelo logout e pelas demais rotas protegidas)
# --------------------------------------------------------------------------- #
async def get_current_session(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> UserSession:
    if credentials is None:
        raise _unauthorized()
    try:
        claims = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],  # lista fixa: impede downgrade de algoritmo
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "sub", "tid", "sid", "typ"]},
        )
        if claims["typ"] != "access":
            raise jwt.InvalidTokenError("tipo de token inválido")
        user_id = uuid.UUID(claims["sub"])
        tenant_id = uuid.UUID(claims["tid"])
        session_id = uuid.UUID(claims["sid"])
    except (jwt.PyJWTError, ValueError):
        raise _unauthorized()

    now = utcnow()
    session = (
        await db.execute(
            select(UserSession).where(
                UserSession.id == session_id,
                UserSession.tenant_id == tenant_id,  # isolamento por tenant
                UserSession.user_id == user_id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > now,
            )
        )
    ).scalar_one_or_none()
    if session is None:
        raise _unauthorized()
    return session


# --------------------------------------------------------------------------- #
# POST /auth/refresh
# --------------------------------------------------------------------------- #
@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    now = utcnow()
    presented_hash = hash_token(body.refresh_token)

    session = (
        await db.execute(
            select(UserSession).where(
                or_(
                    UserSession.current_refresh_hash == presented_hash,
                    UserSession.previous_refresh_hash == presented_hash,
                )
            )
        )
    ).scalar_one_or_none()

    if session is None or session.revoked_at is not None or session.expires_at <= now:
        raise _unauthorized()

    # Reuso de refresh token já rotacionado => possível roubo: encerra a sessão inteira.
    if session.current_refresh_hash != presented_hash:
        await _revoke_session(db, session.id, session.tenant_id)
        raise _unauthorized()

    # Revalida usuário e assinatura, sempre dentro do tenant da sessão.
    row = (
        await db.execute(
            select(User, Tenant)
            .join(Tenant, Tenant.id == User.tenant_id)
            .where(User.id == session.user_id, User.tenant_id == session.tenant_id)
        )
    ).first()
    if row is None or not row.User.is_active:
        await _revoke_session(db, session.id, session.tenant_id)
        raise _unauthorized()
    if not _subscription_is_valid(row.Tenant, now):
        await _revoke_session(db, session.id, session.tenant_id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Assinatura da empresa inativa. Entre em contato com o administrador.",
        )

    # Rotação atômica: só uma requisição concorrente consegue trocar o token.
    new_refresh = secrets.token_urlsafe(48)
    result = await db.execute(
        update(UserSession)
        .where(
            UserSession.id == session.id,
            UserSession.tenant_id == session.tenant_id,
            UserSession.current_refresh_hash == presented_hash,
            UserSession.revoked_at.is_(None),
        )
        .values(
            previous_refresh_hash=presented_hash,
            current_refresh_hash=hash_token(new_refresh),
        )
    )
    if result.rowcount != 1:
        await db.rollback()
        raise _unauthorized()
    await db.commit()

    return TokenResponse(
        access_token=create_access_token(
            user_id=session.user_id, tenant_id=session.tenant_id, session_id=session.id
        ),
        refresh_token=new_refresh,
        expires_in=int(ACCESS_TOKEN_TTL.total_seconds()),
    )


# --------------------------------------------------------------------------- #
# POST /auth/logout
# --------------------------------------------------------------------------- #
@router.post("/logout", response_model=LogoutResponse)
async def logout(
    session: UserSession = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
) -> LogoutResponse:
    """Revoga a sessão atual. Access e refresh tokens associados deixam de funcionar."""
    await _revoke_session(db, session.id, session.tenant_id)
    return LogoutResponse(success=True, detail="Sessão encerrada com sucesso.")