"""
Webhook do gateway de pagamento - plataforma SaaS multilocatária.

Variáveis de ambiente obrigatórias:
  DATABASE_URL                 ex.: postgresql+asyncpg://user:pass@host/db
  PAYMENT_WEBHOOK_SECRETS      segredos separados por vírgula (suporta rotação)

Formato esperado do cabeçalho:  X-Signature: t=<unix_ts>,v1=<hex_hmac>[,v1=<hex_hmac>]
Assinatura = HMAC-SHA256(secret, f"{t}.{corpo_bruto}")
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated

from fastapi import APIRouter, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError
from sqlalchemy import BigInteger, DateTime, Enum as SAEnum, String, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

logger = logging.getLogger("billing.webhook")

# --------------------------------------------------------------------------- #
# Configuração (falha fechada: sem segredo, a aplicação não sobe)
# --------------------------------------------------------------------------- #
def _load_secrets() -> list[bytes]:
    raw = os.environ.get("PAYMENT_WEBHOOK_SECRETS", "")
    secrets = [s.strip().encode() for s in raw.split(",") if s.strip()]
    if not secrets or any(len(s) < 32 for s in secrets):
        raise RuntimeError("PAYMENT_WEBHOOK_SECRETS ausente ou com segredo fraco (<32 bytes)")
    return secrets


WEBHOOK_SECRETS = _load_secrets()
MAX_BODY_BYTES = 64 * 1024          # limita o corpo (mitiga DoS)
SIGNATURE_TOLERANCE_SECONDS = 300   # janela anti-replay

engine = create_async_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class InvoiceStatus(str, Enum):
    OPEN = "open"
    PAYMENT_FAILED = "payment_failed"
    PAID = "paid"
    VOID = "void"
    REFUNDED = "refunded"


class Invoice(Base):
    __tablename__ = "invoices"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(index=True, nullable=False)
    gateway_invoice_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    amount_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    status: Mapped[InvoiceStatus] = mapped_column(SAEnum(InvoiceStatus), nullable=False)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class WebhookEvent(Base):
    """Garante idempotência: o mesmo evento nunca é processado duas vezes."""
    __tablename__ = "webhook_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[int] = mapped_column(nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# --------------------------------------------------------------------------- #
# Validação estrita do payload (A03 - Injection / A04 - Insecure Design)
# --------------------------------------------------------------------------- #
SafeId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_\-]{1,64}$")]
SafeType = Annotated[str, StringConstraints(pattern=r"^[a-z_]+(\.[a-z_]+){1,3}$", max_length=64)]


class InvoiceData(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    invoice_id: SafeId
    amount: int = Field(ge=0, le=10**12)                       # centavos
    currency: Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]


class WebhookPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    id: SafeId
    type: SafeType
    created: int
    data: InvoiceData


# Mapeamento explícito de eventos aceitos -> novo estado
EVENT_TO_STATUS: dict[str, InvoiceStatus] = {
    "invoice.paid": InvoiceStatus.PAID,
    "invoice.payment_failed": InvoiceStatus.PAYMENT_FAILED,
    "invoice.voided": InvoiceStatus.VOID,
    "invoice.refunded": InvoiceStatus.REFUNDED,
}

# Máquina de estados: impede regressões (ex.: paid -> open) por eventos fora de ordem/forjados
ALLOWED_TRANSITIONS: dict[InvoiceStatus, set[InvoiceStatus]] = {
    InvoiceStatus.OPEN: {InvoiceStatus.PAID, InvoiceStatus.PAYMENT_FAILED, InvoiceStatus.VOID},
    InvoiceStatus.PAYMENT_FAILED: {InvoiceStatus.PAID, InvoiceStatus.VOID},
    InvoiceStatus.PAID: {InvoiceStatus.REFUNDED},
    InvoiceStatus.VOID: set(),
    InvoiceStatus.REFUNDED: set(),
}


# --------------------------------------------------------------------------- #
# Autenticidade e integridade (A02 / A07 / A08)
# --------------------------------------------------------------------------- #
_SIG_RE = re.compile(r"^t=(\d{1,12})((?:,v1=[0-9a-f]{64}){1,4})$")


def verify_signature(raw_body: bytes, header: str | None) -> bool:
    if not header or len(header) > 512:
        return False
    match = _SIG_RE.match(header)
    if not match:
        return False

    timestamp = int(match.group(1))
    if abs(time.time() - timestamp) > SIGNATURE_TOLERANCE_SECONDS:   # anti-replay
        return False

    received = [p[3:] for p in match.group(2).split(",") if p.startswith("v1=")]
    signed = str(timestamp).encode() + b"." + raw_body

    ok = False
    for secret in WEBHOOK_SECRETS:                      # aceita segredo antigo e novo
        expected = hmac.new(secret, signed, hashlib.sha256).hexdigest()
        for candidate in received:
            # compare_digest evita timing attack; sem short-circuit entre comparações
            ok |= hmac.compare_digest(expected, candidate)
    return ok


async def read_limited_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Payload too large")

    chunks, total = [], 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Payload too large")
        chunks.append(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
router = APIRouter()


@router.post("/webhooks/payments", include_in_schema=False, status_code=status.HTTP_200_OK)
async def payment_webhook(
    request: Request,
    x_signature: Annotated[str | None, Header(alias="X-Signature")] = None,
) -> dict[str, str]:
    # 1) Content-Type
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Unsupported media type")

    # 2) Corpo bruto (a assinatura é calculada sobre os bytes originais)
    raw_body = await read_limited_body(request)

    # 3) Autenticação da origem ANTES de qualquer parsing/consulta ao banco
    if not verify_signature(raw_body, x_signature):
        logger.warning("webhook rejeitado: assinatura inválida ou expirada")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid signature")

    # 4) Parsing e validação estrita
    try:
        payload = WebhookPayload.model_validate(json.loads(raw_body))
    except (ValueError, ValidationError):
        logger.warning("webhook rejeitado: payload inválido")
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid payload")

    # 5) Evento não suportado: confirma recebimento para o gateway não reenviar
    new_status = EVENT_TO_STATUS.get(payload.type)
    if new_status is None:
        logger.info("evento ignorado event_id=%s type=%s", payload.id, payload.type)
        return {"status": "ignored"}

    # 6) Processamento transacional
    try:
        return await _process_event(payload, new_status)
    except SQLAlchemyError:
        # Falha transitória: 500 genérico (sem detalhes) para que o gateway tente de novo
        logger.exception("erro de banco ao processar event_id=%s", payload.id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error")


async def _process_event(payload: WebhookPayload, new_status: InvoiceStatus) -> dict[str, str]:
    now = datetime.now(timezone.utc)

    async with SessionLocal() as session:  # type: AsyncSession
        async with session.begin():
            # Fatura localizada SOMENTE pelo identificador do gateway.
            # O tenant é derivado do registro no banco, nunca do payload (A01).
            # FOR UPDATE serializa eventos concorrentes da mesma fatura.
            invoice = (
                await session.execute(
                    select(Invoice)
                    .where(Invoice.gateway_invoice_id == payload.data.invoice_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()

            if invoice is None:
                logger.warning("fatura desconhecida event_id=%s invoice=%s",
                               payload.id, payload.data.invoice_id)
                return {"status": "ignored"}

            # Verificação de integridade financeira (A04/A08)
            if new_status is InvoiceStatus.PAID and (
                payload.data.amount != invoice.amount_cents
                or payload.data.currency != invoice.currency
            ):
                logger.error("divergência de valor event_id=%s invoice=%s tenant=%s",
                             payload.id, invoice.gateway_invoice_id, invoice.tenant_id)
                return {"status": "ignored"}

            # Idempotência: PK de event_id; duplicata dispara IntegrityError
            try:
                async with session.begin_nested():
                    session.add(WebhookEvent(
                        event_id=payload.id,
                        event_type=payload.type,
                        tenant_id=invoice.tenant_id,
                        received_at=now,
                    ))
                    await session.flush()
            except IntegrityError:
                return {"status": "duplicate"}

            # Transição de estado válida?
            if invoice.status == new_status:
                return {"status": "noop"}
            if new_status not in ALLOWED_TRANSITIONS[invoice.status]:
                logger.warning("transição inválida event_id=%s invoice=%s %s->%s",
                               payload.id, invoice.gateway_invoice_id,
                               invoice.status.value, new_status.value)
                return {"status": "ignored"}

            invoice.status = new_status
            invoice.updated_at = now
            if new_status is InvoiceStatus.PAID:
                invoice.paid_at = now

            logger.info("fatura atualizada event_id=%s invoice=%s tenant=%s status=%s",
                        payload.id, invoice.gateway_invoice_id,
                        invoice.tenant_id, new_status.value)
            return {"status": "processed"}


# --------------------------------------------------------------------------- #
# App (sem docs públicas / sem CORS, pois é rota servidor-a-servidor)
# --------------------------------------------------------------------------- #
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)