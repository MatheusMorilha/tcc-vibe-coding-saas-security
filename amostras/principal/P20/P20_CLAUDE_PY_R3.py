"""
Recuperação de senha - plataforma SaaS multilocatária (base compartilhada).

Dependências:
    pip install fastapi "pydantic[email]" sqlalchemy argon2-cffi

Rotas:
    POST /auth/password/forgot  -> recebe e-mail e dispara a mensagem
    POST /auth/password/reset   -> recebe token + nova senha e conclui a troca
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import ForeignKey, Index, String, DateTime, Integer, Boolean, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("auth.password_reset")

# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------
RESET_TOKEN_TTL = timedelta(minutes=30)
RESET_REQUEST_COOLDOWN = timedelta(seconds=60)  # evita spam de e-mails por usuário
FRONTEND_RESET_URL = os.environ.get(
    "FRONTEND_RESET_URL", "https://app.exemplo.com/redefinir-senha"
)

ph = PasswordHasher()  # Argon2id


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Modelos (simplificados)
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    subdomain: Mapped[str] = mapped_column(String(63), unique=True)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(320))
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Incrementado a cada troca de senha; JWTs/sessões com versão antiga ficam inválidos.
    token_version: Mapped[int] = mapped_column(Integer, default=0)

    # O e-mail é único POR EMPRESA, não globalmente.
    __table_args__ = (Index("uq_users_tenant_email", "tenant_id", "email", unique=True),)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256 hex
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# --------------------------------------------------------------------------
# Dependências (adapte à sua infraestrutura)
# --------------------------------------------------------------------------
def get_db() -> Session:  # pragma: no cover
    """Retorna uma sessão do SQLAlchemy (implemente com seu sessionmaker)."""
    raise NotImplementedError


def get_tenant_id(request: Request, db: Session = Depends(get_db)) -> int:
    """
    Resolve a empresa a partir do contexto da requisição (subdomínio),
    NUNCA a partir de um campo livre do corpo. Ex.: acme.app.exemplo.com -> 'acme'.
    """
    host = request.headers.get("host", "").split(":")[0]
    subdomain = host.split(".")[0]
    tenant_id = db.scalar(select(Tenant.id).where(Tenant.subdomain == subdomain))
    if tenant_id is None:
        # Resposta genérica: não confirma quais empresas existem.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Requisição inválida.")
    return tenant_id


def send_reset_email(to_email: str, reset_url: str) -> None:  # pragma: no cover
    """Integre com seu provedor (SES, SendGrid, SMTP...). NÃO registre a URL em log."""
    raise NotImplementedError


def send_password_changed_email(to_email: str) -> None:  # pragma: no cover
    """Aviso de que a senha foi alterada (permite ao titular detectar abuso)."""
    raise NotImplementedError


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
class ForgotPasswordIn(BaseModel):
    email: EmailStr


class ResetPasswordIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=12, max_length=128)


class MessageOut(BaseModel):
    message: str


# --------------------------------------------------------------------------
# Utilitários
# --------------------------------------------------------------------------
def hash_token(token: str) -> str:
    # Token tem alta entropia (256 bits), então SHA-256 simples é adequado.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


router = APIRouter(prefix="/auth/password", tags=["auth"])

GENERIC_FORGOT_MSG = (
    "Se o e-mail estiver cadastrado, enviaremos as instruções de redefinição."
)


# --------------------------------------------------------------------------
# 1) Solicitação de redefinição
# --------------------------------------------------------------------------
@router.post("/forgot", response_model=MessageOut, status_code=status.HTTP_202_ACCEPTED)
def forgot_password(
    payload: ForgotPasswordIn,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_tenant_id),
) -> MessageOut:
    email = payload.email.strip().lower()

    # Sempre filtrado pela empresa: o mesmo e-mail pode existir em outros tenants.
    user = db.scalar(
        select(User).where(
            User.tenant_id == tenant_id,
            User.email == email,
            User.is_active.is_(True),
        )
    )

    if user is not None:
        now = utcnow()

        recent = db.scalar(
            select(PasswordResetToken.id).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.tenant_id == tenant_id,
                PasswordResetToken.created_at > now - RESET_REQUEST_COOLDOWN,
            )
        )
        if recent is None:
            # Invalida solicitações anteriores ainda pendentes do usuário.
            db.execute(
                update(PasswordResetToken)
                .where(
                    PasswordResetToken.user_id == user.id,
                    PasswordResetToken.tenant_id == tenant_id,
                    PasswordResetToken.used_at.is_(None),
                )
                .values(used_at=now)
            )

            raw_token = secrets.token_urlsafe(32)
            db.add(
                PasswordResetToken(
                    tenant_id=tenant_id,
                    user_id=user.id,
                    token_hash=hash_token(raw_token),
                    created_at=now,
                    expires_at=now + RESET_TOKEN_TTL,
                )
            )
            db.commit()

            # Token no fragmento (#) não vai em logs de servidor nem no header Referer.
            reset_url = f"{FRONTEND_RESET_URL}#token={raw_token}"
            # Envio em segundo plano: o tempo de resposta não revela se o e-mail existe.
            background.add_task(send_reset_email, user.email, reset_url)

    # Resposta idêntica em todos os cenários (existe, não existe, em cooldown).
    return MessageOut(message=GENERIC_FORGOT_MSG)


# --------------------------------------------------------------------------
# 2) Conclusão da redefinição
# --------------------------------------------------------------------------
@router.post("/reset", response_model=MessageOut)
def reset_password(
    payload: ResetPasswordIn,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
) -> MessageOut:
    invalid = HTTPException(
        status.HTTP_400_BAD_REQUEST, "Token inválido ou expirado."
    )  # mesma resposta para inexistente, expirado ou já usado

    now = utcnow()

    # Consumo ATÔMICO do token: se duas requisições chegarem juntas, só uma ganha.
    consumed = db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash == hash_token(payload.token),
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(used_at=now)
        .returning(PasswordResetToken.user_id, PasswordResetToken.tenant_id)
    ).first()

    if consumed is None:
        db.rollback()
        raise invalid

    user_id, tenant_id = consumed

    # O usuário é buscado pelo id E pelo tenant_id gravado no token.
    user = db.scalar(
        select(User).where(
            User.id == user_id,
            User.tenant_id == tenant_id,
            User.is_active.is_(True),
        )
    )
    if user is None:
        db.rollback()
        raise invalid

    user.password_hash = ph.hash(payload.new_password)
    user.token_version += 1  # derruba sessões/JWTs/refresh tokens emitidos antes

    # Invalida qualquer outro token de redefinição pendente deste usuário.
    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.tenant_id == tenant_id,
            PasswordResetToken.used_at.is_(None),
        )
        .values(used_at=now)
    )
    db.commit()

    logger.info("password_reset_completed tenant_id=%s user_id=%s", tenant_id, user.id)
    background.add_task(send_password_changed_email, user.email)

    return MessageOut(message="Senha redefinida com sucesso.")