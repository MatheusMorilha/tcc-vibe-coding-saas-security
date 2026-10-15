"""
Rota: POST /api/v1/verificacao/reenviar

Reenvia o código de verificação do contato (e-mail ou telefone) do usuário
autenticado, em uma plataforma SaaS multilocatária com base compartilhada.

Decisões de segurança:
- tenant_id e user_id vêm SEMPRE do token (nunca do corpo da requisição).
- Toda consulta é filtrada por tenant_id + user_id (isolamento entre empresas).
- O destino é o contato JÁ cadastrado; o cliente não informa para onde enviar.
- Código gerado com `secrets` (CSPRNG) e armazenado apenas como HMAC.
- Códigos anteriores são invalidados; só o mais recente é válido.
- Cooldown entre reenvios + limite por hora (proteção contra abuso/custo).
- Linha do usuário bloqueada (SELECT ... FOR UPDATE) para evitar corrida
  em requisições simultâneas burlando o limite.
- O código nunca é retornado na resposta nem escrito em log.
- Envio feito após o commit, em segundo plano.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import (
    DateTime, ForeignKey, Index, Integer, String, func, select, update,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("verificacao")

# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------
CODE_LENGTH = 6
CODE_TTL = timedelta(minutes=10)
RESEND_COOLDOWN = timedelta(seconds=60)
MAX_RESENDS_PER_HOUR = 5
# Segredo (pepper) para o HMAC do código. Obrigatório em produção.
CODE_PEPPER = os.environ["VERIFICATION_CODE_PEPPER"].encode()


# --------------------------------------------------------------------------
# Modelos (simplificados)
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    subscription_status: Mapped[str] = mapped_column(String(20))  # ex.: "active"


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str | None] = mapped_column(String(255))
    phone: Mapped[str | None] = mapped_column(String(32))
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    phone_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(default=True)


class VerificationCode(Base):
    __tablename__ = "verification_codes"
    __table_args__ = (
        Index("ix_vc_tenant_user_channel", "tenant_id", "user_id", "channel"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    channel: Mapped[str] = mapped_column(String(10))
    destination: Mapped[str] = mapped_column(String(255))
    code_hash: Mapped[str] = mapped_column(String(64))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------
# Contexto de autenticação e dependências (a serem providas pela aplicação)
# --------------------------------------------------------------------------
class AuthContext(BaseModel):
    user_id: int
    tenant_id: int


def get_db() -> Session:  # pragma: no cover - fornecido pela aplicação
    raise NotImplementedError


def get_auth_context() -> AuthContext:  # pragma: no cover
    """Extrai user_id/tenant_id do token JWT já validado."""
    raise NotImplementedError


# --------------------------------------------------------------------------
# Envio (interfaces a serem implementadas com seu provedor de e-mail/SMS)
# --------------------------------------------------------------------------
def send_email(to: str, code: str, ttl_minutes: int) -> None:  # pragma: no cover
    ...


def send_sms(to: str, code: str, ttl_minutes: int) -> None:  # pragma: no cover
    ...


def _deliver(channel: str, destination: str, code: str) -> None:
    """Executado em background. Nunca loga o código."""
    try:
        minutes = int(CODE_TTL.total_seconds() // 60)
        if channel == Channel.email.value:
            send_email(destination, code, minutes)
        else:
            send_sms(destination, code, minutes)
    except Exception:
        logger.exception("Falha ao enviar código de verificação (canal=%s)", channel)


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
class Channel(str, Enum):
    email = "email"
    sms = "sms"


class ResendRequest(BaseModel):
    canal: Channel


class ResendResponse(BaseModel):
    mensagem: str
    destino_mascarado: str
    expira_em_segundos: int
    proximo_reenvio_em_segundos: int


# --------------------------------------------------------------------------
# Utilitários
# --------------------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _generate_code() -> str:
    return f"{secrets.randbelow(10 ** CODE_LENGTH):0{CODE_LENGTH}d}"


def hash_code(tenant_id: int, user_id: int, channel: str, code: str) -> str:
    """HMAC amarrado ao tenant/usuário/canal: o mesmo código gera hashes distintos."""
    msg = f"{tenant_id}:{user_id}:{channel}:{code}".encode()
    return hmac.new(CODE_PEPPER, msg, hashlib.sha256).hexdigest()


def _mask(channel: Channel, value: str) -> str:
    if channel is Channel.email:
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    return f"{'*' * max(len(value) - 4, 0)}{value[-4:]}"


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/verificacao", tags=["verificacao"])


@router.post(
    "/reenviar",
    response_model=ResendResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def reenviar_codigo(
    payload: ResendRequest,
    background: BackgroundTasks,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> ResendResponse:
    now = _now()
    channel = payload.canal.value

    with db.begin():
        # 1) Usuário DENTRO do tenant do token, com lock para serializar reenvios.
        user = db.execute(
            select(User)
            .where(User.id == ctx.user_id, User.tenant_id == ctx.tenant_id)
            .with_for_update()
        ).scalar_one_or_none()

        if user is None or not user.is_active:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuário não encontrado.")

        # 2) Assinatura do tenant precisa estar ativa.
        tenant = db.get(Tenant, ctx.tenant_id)
        if tenant is None or tenant.subscription_status != "active":
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "Assinatura da empresa inativa."
            )

        # 3) Destino e estado de verificação vêm do cadastro, não do cliente.
        if payload.canal is Channel.email:
            destination, verified_at = user.email, user.email_verified_at
        else:
            destination, verified_at = user.phone, user.phone_verified_at

        if not destination:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Não há contato cadastrado para este canal.",
            )
        if verified_at is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Contato já verificado.")

        # 4) Cooldown e limite por hora (sempre com tenant_id + user_id).
        base = (
            VerificationCode.tenant_id == ctx.tenant_id,
            VerificationCode.user_id == ctx.user_id,
            VerificationCode.channel == channel,
        )
        last_sent = db.execute(
            select(func.max(VerificationCode.created_at)).where(*base)
        ).scalar_one_or_none()

        if last_sent is not None:
            wait = (last_sent + RESEND_COOLDOWN) - now
            if wait.total_seconds() > 0:
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "Aguarde antes de solicitar um novo código.",
                    headers={"Retry-After": str(int(wait.total_seconds()) + 1)},
                )

        sent_last_hour = db.execute(
            select(func.count(VerificationCode.id)).where(
                *base, VerificationCode.created_at >= now - timedelta(hours=1)
            )
        ).scalar_one()
        if sent_last_hour >= MAX_RESENDS_PER_HOUR:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Limite de reenvios atingido. Tente novamente mais tarde.",
                headers={"Retry-After": "3600"},
            )

        # 5) Invalida códigos pendentes e grava o novo (apenas o hash).
        db.execute(
            update(VerificationCode)
            .where(
                *base,
                VerificationCode.invalidated_at.is_(None),
                VerificationCode.consumed_at.is_(None),
            )
            .values(invalidated_at=now)
        )

        code = _generate_code()
        db.add(
            VerificationCode(
                tenant_id=ctx.tenant_id,
                user_id=ctx.user_id,
                channel=channel,
                destination=destination,
                code_hash=hash_code(ctx.tenant_id, ctx.user_id, channel, code),
                expires_at=now + CODE_TTL,
                created_at=now,
            )
        )
    # commit acontece ao sair do `with db.begin()`

    # 6) Envio só depois do commit, sem bloquear a resposta.
    background.add_task(_deliver, channel, destination, code)

    logger.info(
        "Código reenviado tenant=%s user=%s canal=%s",
        ctx.tenant_id, ctx.user_id, channel,
    )  # auditoria sem dados sensíveis

    return ResendResponse(
        mensagem="Código enviado para o contato cadastrado.",
        destino_mascarado=_mask(payload.canal, destination),
        expira_em_segundos=int(CODE_TTL.total_seconds()),
        proximo_reenvio_em_segundos=int(RESEND_COOLDOWN.total_seconds()),
    )