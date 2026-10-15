"""
POST /api/v1/contact-verification/resend

Reenvia o código de verificação do contato (e-mail ou telefone) do usuário
autenticado, em uma plataforma SaaS multilocatária com base compartilhada.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, func, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("contact_verification")

# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------
CODE_LENGTH = 6
CODE_TTL = timedelta(minutes=10)
RESEND_COOLDOWN = timedelta(seconds=60)      # intervalo mínimo entre reenvios
MAX_SENDS_PER_USER_HOUR = 5                  # limite por usuário
MAX_SENDS_PER_TENANT_HOUR = 200              # limite por empresa (anti-abuso/custo)
CODE_PEPPER = os.environ["VERIFICATION_CODE_PEPPER"].encode()  # segredo do servidor


# --------------------------------------------------------------------------
# Modelos (simplificados)
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(index=True)
    email: Mapped[str | None] = mapped_column(String(255))
    phone: Mapped[str | None] = mapped_column(String(32))
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    phone_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(default=True)


class ContactVerification(Base):
    __tablename__ = "contact_verifications"
    __table_args__ = (
        Index("ix_cv_user_created", "tenant_id", "user_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    channel: Mapped[str] = mapped_column(String(10))            # "email" | "sms"
    destination: Mapped[str] = mapped_column(String(255))       # contato no momento do envio
    code_hash: Mapped[str] = mapped_column(String(64))          # nunca o código em claro
    attempts: Mapped[int] = mapped_column(Integer, default=0)   # tentativas de confirmação
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------
# Dependências (a implementar conforme a infraestrutura da plataforma)
# --------------------------------------------------------------------------
class AuthContext(BaseModel):
    user_id: int
    tenant_id: int


def get_db() -> Session: ...                      # sessão por requisição
def get_auth_context() -> AuthContext: ...        # extrai user_id/tenant_id do JWT validado


class Notifier(Protocol):
    def send(self, channel: str, destination: str, code: str) -> None: ...


def get_notifier() -> Notifier: ...               # adaptador de e-mail/SMS


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def generate_code() -> str:
    """Código numérico com CSPRNG (nunca usar `random`)."""
    return f"{secrets.randbelow(10 ** CODE_LENGTH):0{CODE_LENGTH}d}"


def hash_code(code: str, tenant_id: int, user_id: int) -> str:
    """HMAC com pepper + escopo (tenant/usuário): o hash não é reaproveitável entre contas."""
    msg = f"{tenant_id}:{user_id}:{code}".encode()
    return hmac.new(CODE_PEPPER, msg, hashlib.sha256).hexdigest()


def mask_destination(channel: str, value: str) -> str:
    if channel == "email":
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    return f"{'*' * max(len(value) - 4, 0)}{value[-4:]}"


def retry_after(seconds: float) -> int:
    return max(int(seconds) + 1, 1)


def deliver_code(notifier: Notifier, channel: str, destination: str, code: str) -> None:
    """Executa fora do ciclo da requisição. Jamais registrar o código em log."""
    try:
        notifier.send(channel, destination, code)
    except Exception:
        logger.exception("Falha ao enviar código de verificação (canal=%s)", channel)


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/contact-verification", tags=["contact-verification"])


class ResendRequest(BaseModel):
    channel: Literal["email", "sms"] = "email"   # escolhe apenas ENTRE contatos já cadastrados


class ResendResponse(BaseModel):
    destination: str          # mascarado
    channel: str
    expires_in_seconds: int
    resend_available_in_seconds: int


@router.post("/resend", response_model=ResendResponse, status_code=status.HTTP_202_ACCEPTED)
def resend_verification_code(
    payload: ResendRequest,
    background: BackgroundTasks,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
    notifier: Notifier = Depends(get_notifier),
):
    now = utcnow()

    # 1) Usuário sempre filtrado por tenant + id vindos do token.
    #    FOR UPDATE serializa reenvios concorrentes do mesmo usuário
    #    (evita burlar o cooldown com requisições paralelas).
    user = db.execute(
        select(User)
        .where(
            User.id == ctx.user_id,
            User.tenant_id == ctx.tenant_id,
            User.is_active.is_(True),
        )
        .with_for_update()
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuário não encontrado.")

    # 2) Destinatário = contato cadastrado. Nunca aceito no corpo da requisição,
    #    para a rota não virar um relay de spam/SMS para terceiros.
    if payload.channel == "email":
        destination, verified_at = user.email, user.email_verified_at
    else:
        destination, verified_at = user.phone, user.phone_verified_at

    if not destination:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Não há contato cadastrado para este canal.")
    if verified_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Este contato já foi verificado.")

    # 3) Cooldown entre reenvios.
    last_sent = db.execute(
        select(func.max(ContactVerification.created_at)).where(
            ContactVerification.tenant_id == ctx.tenant_id,
            ContactVerification.user_id == user.id,
            ContactVerification.channel == payload.channel,
        )
    ).scalar_one()
    if last_sent and now - last_sent < RESEND_COOLDOWN:
        wait = (RESEND_COOLDOWN - (now - last_sent)).total_seconds()
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Aguarde antes de solicitar um novo código.",
            headers={"Retry-After": str(retry_after(wait))},
        )

    # 4) Limites por hora: usuário e empresa (protege custo de SMS/e-mail e reputação do remetente).
    hour_ago = now - timedelta(hours=1)
    sent_user = db.execute(
        select(func.count()).select_from(ContactVerification).where(
            ContactVerification.tenant_id == ctx.tenant_id,
            ContactVerification.user_id == user.id,
            ContactVerification.created_at >= hour_ago,
        )
    ).scalar_one()
    sent_tenant = db.execute(
        select(func.count()).select_from(ContactVerification).where(
            ContactVerification.tenant_id == ctx.tenant_id,
            ContactVerification.created_at >= hour_ago,
        )
    ).scalar_one()
    if sent_user >= MAX_SENDS_PER_USER_HOUR or sent_tenant >= MAX_SENDS_PER_TENANT_HOUR:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Limite de envios atingido. Tente novamente mais tarde.",
            headers={"Retry-After": "3600"},
        )

    # 5) Invalida códigos pendentes anteriores e grava o novo (hash), na mesma transação.
    db.execute(
        update(ContactVerification)
        .where(
            ContactVerification.tenant_id == ctx.tenant_id,
            ContactVerification.user_id == user.id,
            ContactVerification.channel == payload.channel,
            ContactVerification.consumed_at.is_(None),
            ContactVerification.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )

    code = generate_code()
    db.add(
        ContactVerification(
            tenant_id=ctx.tenant_id,
            user_id=user.id,
            channel=payload.channel,
            destination=destination,
            code_hash=hash_code(code, ctx.tenant_id, user.id),
            created_at=now,
            expires_at=now + CODE_TTL,
        )
    )
    db.commit()  # só envia depois de persistir

    # 6) Envio assíncrono; o código nunca volta na resposta HTTP.
    background.add_task(deliver_code, notifier, payload.channel, destination, code)

    logger.info(
        "Código de verificação reenviado tenant=%s user=%s canal=%s",
        ctx.tenant_id, user.id, payload.channel,
    )
    return ResendResponse(
        destination=mask_destination(payload.channel, destination),
        channel=payload.channel,
        expires_in_seconds=int(CODE_TTL.total_seconds()),
        resend_available_in_seconds=int(RESEND_COOLDOWN.total_seconds()),
    )