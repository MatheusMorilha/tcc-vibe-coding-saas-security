"""
Webhook do gateway de pagamento - plataforma SaaS multilocatária.

Garantias implementadas:
  1. Autenticidade: assinatura HMAC-SHA256 sobre o corpo BRUTO + timestamp
     (comparação em tempo constante e janela anti-replay).
  2. Isolamento de tenant: o tenant NUNCA vem do payload. É derivado da fatura
     localizada pelo ID do gateway, e toda atualização subsequente é feita
     com esse tenant_id.
  3. Idempotência: event_id único; reentregas do gateway são ignoradas.
  4. Consistência: transição de estado validada, linha da fatura travada
     (SELECT ... FOR UPDATE) e valor conferido antes de marcar como paga.
  5. Atomicidade: registro do evento + fatura + assinatura na mesma transação.
"""
import hashlib
import hmac
import logging
import os
import time
from datetime import datetime, timezone
from enum import Enum

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ValidationError
from sqlalchemy import DateTime, ForeignKey, Integer, String, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("webhooks.payments")

WEBHOOK_SECRET = os.environ["PAYMENT_WEBHOOK_SECRET"]  # falha cedo se ausente
SIGNATURE_TOLERANCE_SECONDS = 300
MAX_BODY_BYTES = 256 * 1024


# --------------------------------------------------------------------------
# Modelos (substitua pelos modelos reais da aplicação)
# --------------------------------------------------------------------------
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
    tenant_id: Mapped[int] = mapped_column(Integer, index=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id"))
    gateway_invoice_id: Mapped[str] = mapped_column(String(100), unique=True)
    amount_cents: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3))
    status: Mapped[str] = mapped_column(String(20), default=InvoiceStatus.PENDING.value)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, index=True)
    status: Mapped[str] = mapped_column(String(20), default="past_due")


class WebhookEvent(Base):
    """Tabela de idempotência: event_id único garante processamento único."""
    __tablename__ = "webhook_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(100), unique=True)
    event_type: Mapped[str] = mapped_column(String(100))
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


def get_db():  # injete aqui a sua sessão real
    raise NotImplementedError("Conecte get_db à sua SessionLocal")


# --------------------------------------------------------------------------
# Schema do payload (ajuste ao seu gateway)
# --------------------------------------------------------------------------
class InvoiceData(BaseModel):
    invoice_id: str          # ID da fatura NO GATEWAY
    amount_cents: int
    currency: str


class WebhookPayload(BaseModel):
    event_id: str
    type: str
    data: InvoiceData


EVENT_TO_STATUS = {
    "invoice.paid": InvoiceStatus.PAID,
    "invoice.payment_failed": InvoiceStatus.FAILED,
    "invoice.canceled": InvoiceStatus.CANCELED,
    "invoice.refunded": InvoiceStatus.REFUNDED,
}

ALLOWED_TRANSITIONS = {
    InvoiceStatus.PENDING: {InvoiceStatus.PAID, InvoiceStatus.FAILED, InvoiceStatus.CANCELED},
    InvoiceStatus.FAILED: {InvoiceStatus.PAID, InvoiceStatus.CANCELED},  # retentativa
    InvoiceStatus.PAID: {InvoiceStatus.REFUNDED},
    InvoiceStatus.CANCELED: set(),
    InvoiceStatus.REFUNDED: set(),
}


# --------------------------------------------------------------------------
# Verificação de assinatura
# Header esperado: X-Signature: t=<unix_ts>,v1=<hex_hmac_sha256>
# HMAC calculado sobre: b"<t>." + corpo_bruto
# --------------------------------------------------------------------------
def verify_signature(raw_body: bytes, header: str | None) -> None:
    if not header:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Assinatura ausente")
    try:
        parts = dict(item.split("=", 1) for item in header.split(","))
        timestamp = int(parts["t"])
        received_sig = parts["v1"]
    except (KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Assinatura malformada")

    if abs(time.time() - timestamp) > SIGNATURE_TOLERANCE_SECONDS:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Timestamp fora da janela")

    expected = hmac.new(
        WEBHOOK_SECRET.encode(), f"{timestamp}.".encode() + raw_body, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, received_sig):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Assinatura inválida")


# --------------------------------------------------------------------------
# Processamento (síncrono, executado em threadpool)
# --------------------------------------------------------------------------
def process_event(db: Session, payload: WebhookPayload) -> dict:
    target_status = EVENT_TO_STATUS.get(payload.type)
    if target_status is None:
        # Evento que não nos interessa: confirma (2xx) para o gateway não reenviar.
        return {"result": "ignored", "reason": "event_type_not_handled"}

    try:
        # 1) Idempotência: o INSERT falha se o event_id já foi processado.
        db.add(WebhookEvent(event_id=payload.event_id, event_type=payload.type))
        db.flush()
    except IntegrityError:
        db.rollback()
        return {"result": "duplicate"}

    # 2) Localiza a fatura pelo ID do gateway (único globalmente) e trava a linha.
    invoice = db.execute(
        select(Invoice)
        .where(Invoice.gateway_invoice_id == payload.data.invoice_id)
        .with_for_update()
    ).scalar_one_or_none()

    if invoice is None:
        # Pode ser corrida com a criação da fatura: 404 faz o gateway reenviar.
        db.rollback()
        logger.warning("Fatura desconhecida no webhook: %s", payload.data.invoice_id)
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Fatura não encontrada")

    tenant_id = invoice.tenant_id  # tenant vem do BANCO, nunca do payload

    # 3) Transição de estado válida? (protege contra eventos fora de ordem)
    current = InvoiceStatus(invoice.status)
    if current == target_status:
        db.commit()  # preserva o registro do evento
        return {"result": "noop", "reason": "already_in_state"}

    if target_status not in ALLOWED_TRANSITIONS[current]:
        db.commit()
        logger.warning(
            "Transição ignorada tenant=%s invoice=%s %s -> %s",
            tenant_id, invoice.id, current.value, target_status.value,
        )
        return {"result": "ignored", "reason": "invalid_transition"}

    # 4) Confere valor/moeda antes de reconhecer pagamento.
    if target_status == InvoiceStatus.PAID and (
        payload.data.amount_cents != invoice.amount_cents
        or payload.data.currency.upper() != invoice.currency.upper()
    ):
        db.commit()
        logger.error(
            "Divergência de valor tenant=%s invoice=%s esperado=%s/%s recebido=%s/%s",
            tenant_id, invoice.id, invoice.amount_cents, invoice.currency,
            payload.data.amount_cents, payload.data.currency,
        )
        return {"result": "ignored", "reason": "amount_mismatch"}

    # 5) Aplica a mudança.
    invoice.status = target_status.value
    if target_status == InvoiceStatus.PAID:
        invoice.paid_at = datetime.now(timezone.utc)
        subscription = db.execute(
            select(Subscription).where(
                Subscription.id == invoice.subscription_id,
                Subscription.tenant_id == tenant_id,  # escopo explícito
            )
        ).scalar_one_or_none()
        if subscription is not None:
            subscription.status = "active"

    db.commit()
    logger.info(
        "Fatura atualizada tenant=%s invoice=%s %s -> %s",
        tenant_id, invoice.id, current.value, target_status.value,
    )
    return {"result": "processed"}


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/payments", status_code=status.HTTP_200_OK)
async def payment_webhook(
    request: Request,
    x_signature: str | None = Header(default=None, alias="X-Signature"),
    db: Session = Depends(get_db),
):
    # Corpo bruto: a assinatura é calculada sobre os bytes exatos recebidos.
    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Corpo muito grande")

    verify_signature(raw_body, x_signature)  # só interpreta depois de autenticar

    try:
        payload = WebhookPayload.model_validate_json(raw_body)
    except ValidationError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Payload inválido")

    try:
        return await run_in_threadpool(process_event, db, payload)
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        logger.exception("Erro ao processar webhook event_id=%s", payload.event_id)
        # 5xx => o gateway fará nova tentativa (seguro, pois o handler é idempotente)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Erro interno")