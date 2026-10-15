"""
auth_routes.py
Rotas de renovação de token de sessão e encerramento de sessão
para uma plataforma SaaS multilocatária (base compartilhada).

Decisões de segurança:
- Access token JWT curto (15 min), carrega tenant_id, user_id e sid (id da sessão).
- Refresh token opaco (aleatório, 256 bits), armazenado apenas como hash SHA-256.
- Rotação a cada renovação; reutilização de token já usado revoga a sessão inteira.
- Todas as consultas são filtradas por tenant_id (isolamento entre empresas).
- Renovação revalida usuário ativo e assinatura ativa da empresa.
- Logout revoga a sessão no servidor; o access token deixa de valer imediatamente,
  pois get_current_claims confere o estado da sessão a cada requisição.
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt  # PyJWT
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, Boolean, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# --------------------------------------------------------------------------
# Configuração (em produção, carregar de variáveis de ambiente / secret manager)
# --------------------------------------------------------------------------
JWT_SECRET = "TROCAR-POR-SEGREDO-FORTE-DO-AMBIENTE"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL = timedelta(minutes=15)
REFRESH_TOKEN_TTL = timedelta(days=30)
ACTIVE_SUBSCRIPTION_STATUSES = {"active", "trialing"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Modelos (Tenant e User normalmente já existem; aqui estão mínimos)
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    subscription_status: Mapped[str] = mapped_column(String(20))


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user_sessions.id"), index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# --------------------------------------------------------------------------
# Dependência de banco (substituir pela do projeto)
# --------------------------------------------------------------------------
def get_db():  # pragma: no cover
    raise NotImplementedError("Injete a sessão do SQLAlchemy do projeto.")


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class LogoutRequest(BaseModel):
    all_devices: bool = False


class MessageResponse(BaseModel):
    detail: str


# --------------------------------------------------------------------------
# Utilitários de token
# --------------------------------------------------------------------------
def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_access_token(tenant_id: uuid.UUID, user_id: uuid.UUID, session_id: uuid.UUID) -> str:
    now = utcnow()
    payload = {
        "sub": str(user_id),
        "tid": str(tenant_id),
        "sid": str(session_id),
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def issue_refresh_token(db: Session, session_obj: UserSession) -> str:
    raw = secrets.token_urlsafe(48)
    db.add(
        RefreshToken(
            session_id=session_obj.id,
            tenant_id=session_obj.tenant_id,
            user_id=session_obj.user_id,
            token_hash=hash_token(raw),
            expires_at=utcnow() + REFRESH_TOKEN_TTL,
        )
    )
    return raw


def _unauthorized(detail: str = "Credenciais inválidas ou sessão expirada.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


# --------------------------------------------------------------------------
# Autenticação do access token (usada pelo logout e demais rotas protegidas)
# --------------------------------------------------------------------------
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_claims(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> dict:
    if credentials is None:
        raise _unauthorized()
    try:
        claims = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],  # lista fixa: evita confusão de algoritmo
            options={"require": ["exp", "sub", "tid", "sid", "jti"]},
        )
    except jwt.PyJWTError:
        raise _unauthorized()
    if claims.get("type") != "access":
        raise _unauthorized()

    # A sessão precisa existir, pertencer ao mesmo tenant/usuário e não estar revogada.
    session_obj = db.scalar(
        select(UserSession).where(
            UserSession.id == uuid.UUID(claims["sid"]),
            UserSession.tenant_id == uuid.UUID(claims["tid"]),
            UserSession.user_id == uuid.UUID(claims["sub"]),
            UserSession.revoked_at.is_(None),
        )
    )
    if session_obj is None:
        raise _unauthorized()
    return claims


# --------------------------------------------------------------------------
# Rotas
# --------------------------------------------------------------------------
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/refresh", response_model=TokenResponse)
def refresh_session_token(
    body: RefreshRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Renova o token de sessão. Rotaciona o refresh token a cada chamada."""
    now = utcnow()

    # with_for_update evita que duas requisições simultâneas usem o mesmo token.
    token = db.scalar(
        select(RefreshToken)
        .where(RefreshToken.token_hash == hash_token(body.refresh_token))
        .with_for_update()
    )
    if token is None:
        raise _unauthorized()

    # Reutilização de token já consumido => possível roubo: derruba a sessão inteira.
    if token.used_at is not None:
        db.execute(
            update(UserSession)
            .where(
                UserSession.id == token.session_id,
                UserSession.tenant_id == token.tenant_id,
                UserSession.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        db.commit()
        raise _unauthorized()

    if token.expires_at <= now:
        raise _unauthorized()

    # Sessão válida, no escopo do tenant do próprio token.
    session_obj = db.scalar(
        select(UserSession).where(
            UserSession.id == token.session_id,
            UserSession.tenant_id == token.tenant_id,
            UserSession.user_id == token.user_id,
            UserSession.revoked_at.is_(None),
        )
    )
    # Usuário continua ativo e pertence ao tenant.
    user = db.scalar(
        select(User).where(
            User.id == token.user_id,
            User.tenant_id == token.tenant_id,
            User.is_active.is_(True),
        )
    )
    # Assinatura da empresa continua ativa.
    tenant = db.scalar(select(Tenant).where(Tenant.id == token.tenant_id))

    if (
        session_obj is None
        or user is None
        or tenant is None
        or tenant.subscription_status not in ACTIVE_SUBSCRIPTION_STATUSES
    ):
        raise _unauthorized()

    # Rotação: consome o token atual e emite um novo.
    token.used_at = now
    new_refresh = issue_refresh_token(db, session_obj)
    new_access = create_access_token(tenant.id, user.id, session_obj.id)
    db.commit()

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=int(ACCESS_TOKEN_TTL.total_seconds()),
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    body: LogoutRequest | None = None,
    claims: dict = Depends(get_current_claims),
    db: Session = Depends(get_db),
) -> MessageResponse:
    """Encerra a sessão atual (ou todas as sessões do usuário, se all_devices=true)."""
    now = utcnow()
    tenant_id = uuid.UUID(claims["tid"])
    user_id = uuid.UUID(claims["sub"])

    stmt = update(UserSession).where(
        UserSession.tenant_id == tenant_id,
        UserSession.user_id == user_id,
        UserSession.revoked_at.is_(None),
    )
    if not (body and body.all_devices):
        stmt = stmt.where(UserSession.id == uuid.UUID(claims["sid"]))
    db.execute(stmt.values(revoked_at=now))
    db.commit()

    return MessageResponse(detail="Sessão encerrada com sucesso.")