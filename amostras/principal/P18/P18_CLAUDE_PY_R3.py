"""
Rota: POST /api/v1/contacts/{contact_id}/verification/resend

Reenvia o código de verificação de um contato (e-mail ou telefone) do
usuário autenticado, em um ambiente SaaS multilocatário com base compartilhada.
"""
import hashlib
import hmac
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

logger = logging.getLogger("verification")

# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------
CODE_LENGTH = 6
CODE_TTL = timedelta(minutes=10)
RESEND_COOLDOWN = timedelta(seconds=60)      # intervalo mínimo entre envios
MAX_SENDS_PER_HOUR = 5                       # limite por contato
MAX_SENDS_PER_HOUR_TENANT = 500              # proteção de custo por empresa
CODE_PEPPER = os.environ["VERIFICATION_CODE_PEPPER"]  # segredo fora do banco


# --------------------------------------------------------------------------
# Modelos (simplificados). Toda tabela de negócio carrega tenant_id.
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class UserContact(Base):
    __tablename__ = "user_contacts"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    channel: Mapped[str] = mapped_column(String(10))        # "email" | "sms"
    destination: Mapped[str] = mapped_column(String(255))   # e-mail ou telefone E.164
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)


class VerificationCode(Base):
    __tablename__ = "verification_codes"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(index=True)
    contact_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user_contacts.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))      # HMAC-SHA256, nunca o código em claro
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    invalidated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# --------------------------------------------------------------------------
# Dependências (a serem fornecidas pela aplicação)
# --------------------------------------------------------------------------
class AuthContext(BaseModel):
    user_id: uuid.UUID
    tenant_id: uuid.UUID   # SEMPRE extraído do token validado, nunca do corpo/URL


async def get_auth_context() -> AuthContext:
    """Valida o JWT/sessão e devolve usuário e tenant. Implementação da plataforma."""
    raise NotImplementedError


async def get_db() -> AsyncSession:
    """Sessão de banco da aplicação."""
    raise NotImplementedError


async def deliver_code(channel: str, destination: str, code: str, tenant_id: uuid.UUID) -> None:
    """Integração com provedor de e-mail/SMS (SES, SendGrid, Twilio...)."""
    raise NotImplementedError


# --------------------------------------------------------------------------
# Utilitários
# --------------------------------------------------------------------------
def generate_code() -> str:
    """Código numérico criptograficamente seguro (secrets, não random)."""
    return f"{secrets.randbelow(10 ** CODE_LENGTH):0{CODE_LENGTH}d}"


def hash_code(code: str, contact_id: uuid.UUID) -> str:
    msg = f"{contact_id}:{code}".encode()
    return hmac.new(CODE_PEPPER.encode(), msg, hashlib.sha256).hexdigest()


def mask_destination(channel: str, destination: str) -> str:
    if channel == "email":
        local, _, domain = destination.partition("@")
        return f"{local[:2]}***@{domain}"
    return f"{destination[:3]}*****{destination[-2:]}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/contacts", tags=["verification"])


class ResendResponse(BaseModel):
    detail: str
    sent_to: str
    channel: Literal["email", "sms"]
    expires_in_seconds: int
    retry_after_seconds: int


@router.post(
    "/{contact_id}/verification/resend",
    response_model=ResendResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def resend_verification_code(
    contact_id: uuid.UUID,
    background: BackgroundTasks,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    now = utcnow()

    async with db.begin():
        # 1) Busca o contato filtrando por tenant E usuário (isolamento multilocatário)
        #    e trava a linha para evitar corrida entre requisições simultâneas.
        contact = (
            await db.execute(
                select(UserContact)
                .where(
                    UserContact.id == contact_id,
                    UserContact.tenant_id == auth.tenant_id,
                    UserContact.user_id == auth.user_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()

        if contact is None:
            # 404 genérico: não revela se o ID existe em outro tenant/usuário
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Contato não encontrado.")

        if contact.is_verified:
            raise HTTPException(status.HTTP_409_CONFLICT, "Contato já verificado.")

        # 2) Limites de envio: cooldown, janela por contato e teto por empresa
        last_sent = (
            await db.execute(
                select(func.max(VerificationCode.created_at)).where(
                    VerificationCode.contact_id == contact.id,
                    VerificationCode.tenant_id == auth.tenant_id,
                )
            )
        ).scalar_one()

        if last_sent and now - last_sent < RESEND_COOLDOWN:
            wait = int((RESEND_COOLDOWN - (now - last_sent)).total_seconds()) + 1
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(wait)},
                content={"detail": "Aguarde antes de solicitar um novo código.",
                         "retry_after_seconds": wait},
            )

        window_start = now - timedelta(hours=1)
        sent_last_hour = (
            await db.execute(
                select(func.count(VerificationCode.id)).where(
                    VerificationCode.contact_id == contact.id,
                    VerificationCode.tenant_id == auth.tenant_id,
                    VerificationCode.created_at >= window_start,
                )
            )
        ).scalar_one()

        if sent_last_hour >= MAX_SENDS_PER_HOUR:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": "3600"},
                content={"detail": "Limite de reenvios atingido. Tente novamente mais tarde."},
            )

        tenant_sent_last_hour = (
            await db.execute(
                select(func.count(VerificationCode.id)).where(
                    VerificationCode.tenant_id == auth.tenant_id,
                    VerificationCode.created_at >= window_start,
                )
            )
        ).scalar_one()

        if tenant_sent_last_hour >= MAX_SENDS_PER_HOUR_TENANT:
            logger.warning("tenant_send_cap_reached tenant=%s", auth.tenant_id)
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": "3600"},
                content={"detail": "Limite de envios da organização atingido."},
            )

        # 3) Invalida códigos pendentes anteriores (só o mais recente é válido)
        await db.execute(
            update(VerificationCode)
            .where(
                VerificationCode.contact_id == contact.id,
                VerificationCode.tenant_id == auth.tenant_id,
                VerificationCode.consumed.is_(False),
                VerificationCode.invalidated.is_(False),
            )
            .values(invalidated=True)
        )

        # 4) Gera o novo código e persiste apenas o hash
        code = generate_code()
        db.add(
            VerificationCode(
                tenant_id=auth.tenant_id,
                contact_id=contact.id,
                code_hash=hash_code(code, contact.id),
                expires_at=now + CODE_TTL,
            )
        )

        channel, destination = contact.channel, contact.destination
    # commit realizado aqui; o envio só ocorre depois de persistir

    # 5) Disparo assíncrono ao destinatário CADASTRADO (nunca vindo da requisição)
    background.add_task(_safe_deliver, channel, destination, code, auth.tenant_id)

    # Log de auditoria sem o código nem o destino completo
    logger.info(
        "verification_code_resent tenant=%s user=%s contact=%s channel=%s",
        auth.tenant_id, auth.user_id, contact_id, channel,
    )

    return ResendResponse(
        detail="Código de verificação enviado.",
        sent_to=mask_destination(channel, destination),
        channel=channel,
        expires_in_seconds=int(CODE_TTL.total_seconds()),
        retry_after_seconds=int(RESEND_COOLDOWN.total_seconds()),
    )


async def _safe_deliver(channel: str, destination: str, code: str, tenant_id: uuid.UUID) -> None:
    try:
        await deliver_code(channel, destination, code, tenant_id)
    except Exception:
        # Nunca logar o código; falha de envio não deve vazar detalhes ao cliente
        logger.exception("verification_delivery_failed tenant=%s channel=%s", tenant_id, channel)