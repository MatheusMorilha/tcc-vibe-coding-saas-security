"""
Rota de webhook do gateway de pagamento para plataforma SaaS multilocatária.

Premissas sobre o gateway (ajuste ao provedor real):
  - Envia POST JSON com os headers:
        X-Webhook-Timestamp: epoch em segundos
        X-Webhook-Signature: hex(HMAC_SHA256(secret, f"{timestamp}.{corpo_bruto}"))
  - Payload:
        {
          "id": "evt_123",                      # id único do evento
          "type": "invoice.paid",
          "data": {
            "invoice_id": "gw_inv_456",         # id da fatura NO GATEWAY
            "amount_cents": 19900,
            "currency": "BRL"
          }
        }

Dependências: fastapi, uvicorn, sqlalchemy>=2.0, pydantic>=2
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from datetime import datetime, timezone
from enum import Enum

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import DateTime, ForeignKey, Integer, String, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

logger = logging.getLogger("webhooks.payments")

# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
WEBHOOK_SECRET = os.environ["PAYMENT_WEBHOOK_SECRET"].encode()  # falha cedo se ausente
TIMESTAMP_TOLERANCE_SECONDS = 300          # janela anti-replay
MAX_BODY_BYTES = 256 * 1024                # evita corpos gigantes

engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


def get_db():
    with SessionLocal() as db:
        yield db


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class InvoiceStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    CANCELED = "canceled"
    REFUNDED = "refunded"


class Invoice(Base):
    __tablename__ = "invoices"

    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    # único globalmente: é a chave pela qual o webhook localiza a fatura
    gateway_invoice_id: Mapped[str] = mapped_column(String(128), unique=True)
    amount_cents: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3))
    status: Mapped[str] = mapped_column(String(16), default=InvoiceStatus.PENDING.value)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class WebhookEvent(Base):
    """Registro de eventos já recebidos: garante idempotência e dá trilha de auditoria."""

    __tablename__ = "webhook_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(128), unique=True)
    event_type: Mapped[str] = mapped_column(String(64))
    company_id: Mapped[int | None] = mapped_column(Integer, index=True)
    outcome: Mapped[str] = mapped_column(String(32))
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


# --------------------------------------------------------------------------- #
# Schemas do payload
# --------------------------------------------------------------------------- #
class EventData(BaseModel):
    model_config = ConfigDict(extra="ignore")

    invoice_id: str = Field(min_length=1, max_length=128)
    amount_cents: int | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, min_length=3, max_length=3)


class WebhookPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1, max_length=128)
    type: str = Field(min_length=1, max_length=64)
    data: EventData


# Evento do gateway -> novo status da fatura
EVENT_TO_STATUS: dict[str, InvoiceStatus] = {
    "invoice.paid": InvoiceStatus.PAID,
    "invoice.payment_failed": InvoiceStatus.FAILED,
    "invoice.canceled": InvoiceStatus.CANCELED,
    "invoice.refunded": InvoiceStatus.REFUNDED,
}

# Máquina de estados: protege contra eventos fora de ordem / regressões indevidas
ALLOWED_TRANSITIONS: dict[InvoiceStatus, set[InvoiceStatus]] = {
    InvoiceStatus.PENDING: {InvoiceStatus.PAID, InvoiceStatus.FAILED, InvoiceStatus.CANCELED},
    InvoiceStatus.FAILED: {InvoiceStatus.PAID, InvoiceStatus.CANCELED},
    InvoiceStatus.PAID: {InvoiceStatus.REFUNDED},
    InvoiceStatus.CANCELED: set(),
    InvoiceStatus.REFUNDED: set(),
}


# --------------------------------------------------------------------------- #
# Verificação de autenticidade
# --------------------------------------------------------------------------- #
def verify_signature(raw_body: bytes, timestamp: str, signature: str) -> None:
    try:
        ts = int(timestamp)
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Assinatura inválida")

    if abs(time.time() - ts) > TIMESTAMP_TOLERANCE_SECONDS:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Timestamp fora da janela")

    signed = timestamp.encode() + b"." + raw_body
    expected = hmac.new(WEBHOOK_SECRET, signed, hashlib.sha256).hexdigest()

    # comparação em tempo constante
    if not hmac.compare_digest(expected, signature.strip().lower()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Assinatura inválida")


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/payments", status_code=status.HTTP_200_OK)
async def payment_webhook(
    request: Request,
    x_webhook_timestamp: str = Header(...),
    x_webhook_signature: str = Header(...),
    db: Session = Depends(get_db),
):
    # 1) Corpo BRUTO: a assinatura deve ser validada antes de qualquer parse
    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Corpo muito grande")

    # 2) Autenticidade (não há sessão/usuário aqui: a assinatura é a autenticação)
    verify_signature(raw_body, x_webhook_timestamp, x_webhook_signature)

    # 3) Parse e validação do conteúdo
    try:
        payload = WebhookPayload.model_validate_json(raw_body)
    except ValidationError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Payload inválido")

    new_status = EVENT_TO_STATUS.get(payload.type)
    if new_status is None:
        # Evento que não nos interessa: confirma recebimento para evitar reentregas
        logger.info("Evento ignorado: type=%s id=%s", payload.type, payload.id)
        return {"status": "ignored"}

    # 4) Tudo em uma única transação
    try:
        # 4.1) Idempotência: o UNIQUE em event_id impede processar duas vezes
        event = WebhookEvent(
            event_id=payload.id, event_type=payload.type, outcome="processing"
        )
        db.add(event)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            logger.info("Evento duplicado: id=%s", payload.id)
            return {"status": "duplicate"}

        # 4.2) Localiza a fatura pelo id do gateway e TRAVA a linha (evita corrida
        #      entre eventos concorrentes da mesma fatura).
        #      O tenant é derivado da própria fatura; nunca de dados do payload.
        invoice = db.execute(
            select(Invoice)
            .where(Invoice.gateway_invoice_id == payload.data.invoice_id)
            .with_for_update()
        ).scalar_one_or_none()

        if invoice is None:
            # Pode ser corrida (webhook chegou antes do commit da fatura):
            # 404 + rollback do registro do evento => o gateway tentará de novo
            db.rollback()
            logger.warning("Fatura não encontrada: gateway_invoice_id=%s", payload.data.invoice_id)
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Fatura não encontrada")

        event.company_id = invoice.company_id

        # 4.3) Conferência de consistência com o que foi cobrado
        if new_status is InvoiceStatus.PAID:
            if (
                payload.data.amount_cents is not None
                and payload.data.amount_cents != invoice.amount_cents
            ) or (
                payload.data.currency is not None
                and payload.data.currency.upper() != invoice.currency.upper()
            ):
                event.outcome = "amount_mismatch"
                db.commit()
                logger.error(
                    "Divergência de valor: company=%s invoice=%s esperado=%s/%s recebido=%s/%s",
                    invoice.company_id, invoice.id, invoice.amount_cents, invoice.currency,
                    payload.data.amount_cents, payload.data.currency,
                )
                # 200: reentregar não resolve; fica registrado para revisão manual
                return {"status": "amount_mismatch"}

        # 4.4) Transição de estado
        current = InvoiceStatus(invoice.status)
        if current is new_status:
            event.outcome = "noop"
        elif new_status in ALLOWED_TRANSITIONS[current]:
            now = datetime.now(timezone.utc)
            invoice.status = new_status.value
            invoice.updated_at = now
            if new_status is InvoiceStatus.PAID:
                invoice.paid_at = now
            event.outcome = "applied"
            # Gancho: aqui você enfileiraria efeitos colaterais (liberar plano,
            # enviar e-mail, etc.) via outbox/fila, nunca chamadas lentas inline.
        else:
            event.outcome = "invalid_transition"
            logger.warning(
                "Transição inválida: company=%s invoice=%s %s -> %s",
                invoice.company_id, invoice.id, current.value, new_status.value,
            )

        db.commit()
        return {"status": event.outcome}

    except HTTPException:
        raise
    except Exception:
        db.rollback()
        logger.exception("Falha ao processar webhook id=%s", payload.id)
        # 500 => o gateway reenviará; a idempotência garante segurança
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Erro interno")