"""
Recuperação de senha em plataforma SaaS multilocatária.

Dependências:
    pip install fastapi "pydantic[email]" sqlalchemy argon2-cffi

Rotas:
    POST /auth/password/forgot  -> recebe e-mail, dispara mensagem de redefinição
    POST /auth/password/reset   -> recebe token + nova senha, conclui a alteração
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Iterator

from argon2 import PasswordHasher
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint, select, update,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("auth.password_reset")

# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
RESET_TOKEN_TTL = timedelta(minutes=30)      # validade curta
RESET_REQUEST_COOLDOWN = timedelta(seconds=60)  # evita spam de e-mails por usuário
MIN_PASSWORD_LENGTH = 10

ph = PasswordHasher()  # Argon2id


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Modelos (simplificados; adapte aos seus modelos existentes)
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    subdomain: Mapped[str] = mapped_column(String(63), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    frontend_url: Mapped[str] = mapped_column(String(255))  # ex.: https://acme.app.com
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class User(Base):
    __tablename__ = "users"
    # O e-mail é único POR tenant, não globalmente.
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Incrementado a cada troca de senha; sessões/JWTs com versão antiga ficam inválidos.
    token_version: Mapped[int] = mapped_column(Integer, default=0)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    # Guardamos apenas o HASH do token; o valor em claro só existe no e-mail.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# --------------------------------------------------------------------------- #
# Dependências (ajuste get_db / get_tenant à sua infraestrutura)
# --------------------------------------------------------------------------- #
def get_db() -> Iterator[Session]:
    raise NotImplementedError("Injete sua SessionLocal aqui")


def get_tenant(request: Request, db: Session = Depends(get_db)) -> Tenant:
    """
    Resolve o tenant pelo subdomínio (acme.app.com -> 'acme').
    O tenant NUNCA é aceito do corpo da requisição.
    """
    host = request.headers.get("host", "").split(":")[0]
    subdomain = host.split(".")[0] if host.count(".") >= 2 else ""
    tenant = db.scalar(
        select(Tenant).where(Tenant.subdomain == subdomain, Tenant.is_active.is_(True))
    )
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant não encontrado.")
    return tenant


def send_reset_email(to_email: str, tenant_name: str, reset_url: str) -> None:
    """Integre com SES/SendGrid/SMTP. Nunca registre o reset_url em logs."""
    raise NotImplementedError


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class ForgotPasswordIn(BaseModel):
    email: EmailStr


class ResetPasswordIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=128)


class MessageOut(BaseModel):
    message: str


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def validate_password_strength(password: str) -> None:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"mínimo de {MIN_PASSWORD_LENGTH} caracteres")
    if not re.search(r"[a-z]", password):
        problems.append("uma letra minúscula")
    if not re.search(r"[A-Z]", password):
        problems.append("uma letra maiúscula")
    if not re.search(r"\d", password):
        problems.append("um número")
    if problems:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Senha fraca. Requisitos: " + ", ".join(problems) + ".",
        )


# --------------------------------------------------------------------------- #
# Rotas
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/auth/password", tags=["auth"])

GENERIC_FORGOT_MESSAGE = (
    "Se existir uma conta com este e-mail, enviaremos as instruções de redefinição."
)


@router.post("/forgot", response_model=MessageOut, status_code=status.HTTP_202_ACCEPTED)
def forgot_password(
    payload: ForgotPasswordIn,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(get_tenant),
) -> MessageOut:
    """
    Sempre responde 202 com a MESMA mensagem, exista o e-mail ou não
    (evita enumeração de usuários). O envio ocorre em background para
    não vazar a diferença pelo tempo de resposta.
    """
    email = payload.email.strip().lower()

    user = db.scalar(
        select(User).where(
            User.tenant_id == tenant.id,   # isolamento entre empresas
            User.email == email,
            User.is_active.is_(True),
        )
    )

    if user is not None:
        now = utcnow()

        # Cooldown: se já houve solicitação recente, não gera outro e-mail.
        recent = db.scalar(
            select(PasswordResetToken.id).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.created_at > now - RESET_REQUEST_COOLDOWN,
            )
        )
        if recent is None:
            # Invalida tokens anteriores ainda pendentes (só o último link vale).
            db.execute(
                update(PasswordResetToken)
                .where(
                    PasswordResetToken.user_id == user.id,
                    PasswordResetToken.used_at.is_(None),
                )
                .values(used_at=now)
            )

            raw_token = secrets.token_urlsafe(32)  # 256 bits de entropia
            db.add(
                PasswordResetToken(
                    tenant_id=tenant.id,
                    user_id=user.id,
                    token_hash=hash_token(raw_token),
                    expires_at=now + RESET_TOKEN_TTL,
                )
            )
            db.commit()

            # Token no fragmento (#) não vai para logs de servidor/proxy nem Referer.
            reset_url = f"{tenant.frontend_url.rstrip('/')}/redefinir-senha#token={raw_token}"
            background.add_task(send_reset_email, user.email, tenant.name, reset_url)

            logger.info("password_reset_requested tenant=%s user=%s", tenant.id, user.id)

    return MessageOut(message=GENERIC_FORGOT_MESSAGE)


@router.post("/reset", response_model=MessageOut)
def reset_password(
    payload: ResetPasswordIn,
    db: Session = Depends(get_db),
    tenant: Tenant = Depends(get_tenant),
) -> MessageOut:
    """Valida o token e troca a senha. Token é de uso único e restrito ao tenant."""
    invalid = HTTPException(
        status.HTTP_400_BAD_REQUEST, "Link de redefinição inválido ou expirado."
    )

    validate_password_strength(payload.new_password)

    now = utcnow()
    token_hash = hash_token(payload.token)

    # "Consome" o token de forma atômica: se duas requisições chegarem ao mesmo
    # tempo, apenas uma encontra used_at IS NULL e altera a linha (anti-replay).
    consumed = db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.tenant_id == tenant.id,  # token de outra empresa é inválido
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(used_at=now)
        .returning(PasswordResetToken.user_id)
    ).scalar_one_or_none()

    if consumed is None:
        db.rollback()
        raise invalid

    user = db.scalar(
        select(User).where(
            User.id == consumed,
            User.tenant_id == tenant.id,
            User.is_active.is_(True),
        )
    )
    if user is None:
        db.rollback()
        raise invalid

    user.password_hash = ph.hash(payload.new_password)
    user.token_version += 1  # revoga sessões/JWTs emitidos antes da troca

    # Invalida quaisquer outros tokens pendentes do usuário.
    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        )
        .values(used_at=now)
    )
    db.commit()

    logger.info("password_reset_completed tenant=%s user=%s", tenant.id, user.id)
    # Opcional: enviar e-mail de aviso "sua senha foi alterada".
    return MessageOut(message="Senha redefinida com sucesso.")