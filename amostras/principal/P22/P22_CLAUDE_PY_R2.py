"""
Webhook do gateway de pagamento - plataforma SaaS multilocatária.

Fluxo:
  1. Lê o corpo BRUTO (necessário para validar a assinatura).
  2. Valida assinatura HMAC-SHA256 + janela de tempo (anti-replay).
  3. Interpreta e valida o payload (Pydantic).
  4. Em UMA transação: registra o evento (idempotência), trava a fatura,
     confere tenant/valor e aplica a transição de estado permitida.
"""
import hashlib
import hmac
import logging
import os
import time
from datetime import datetime, timezone
from enum import Enum

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import BigInteger, DateTime, ForeignKey, String, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("webhooks.payments")
router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# O segredo vem do ambiente/cofre de segredos, nunca do código.
WEBHOOK_SECRET = os.environ["PAYMENT_WEBHOOK_SECRET"].encode()
SIGNATURE_TOLERANCE_SECONDS = 300
MAX_BODY_BYTES = 256 * 1024


# --------------------------------------------------------------------------
# Modelos (simplificados; adapte ao seu schema)
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class InvoiceStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    CANCELED = "canceled"
    REFUNDED = "refunded"


class Company(Base):
    __tablename__ = "companies"
    id: Mapped[int] = mapped_column(primary_key=True)
    gateway_customer_id: Mapped[str] = mapped_column(String(64), unique=True)


class Invoice(Base):
    __tablename__ = "invoices"
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    gateway_invoice_id: Mapped[str] = mapped_column(String(64), unique=True)
    amount_cents: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(16), default=InvoiceStatus.PENDING.value)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class WebhookEvent(Base):
    """Registro de eventos já processados (idempotência)."""
    __tablename__ = "webhook_events"
    __table_args__ = (UniqueConstraint("gateway_event_id", name="uq_webhook_event_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    gateway_event_id: Mapped[str] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def get_db() -> Session:  # substitua pela sua dependência real de sessão
    raise NotImplementedError


# --------------------------------------------------------------------------
# Payload
# --------------------------------------------------------------------------
class EventType(str, Enum):
    INVOICE_PAID = "invoice.paid"
    INVOICE_PAYMENT_FAILED = "invoice.payment_failed"
    INVOICE_CANCELED = "invoice.canceled"
    INVOICE_REFUNDED = "invoice.refunded"


class InvoiceData(BaseModel):
    invoice_id: str = Field(min_length=1, max_length=64)
    customer_id: str = Field(min_length=1, max_length=64)
    amount_cents: int = Field(ge=0)


class WebhookPayload(BaseModel):
    event_id: str = Field(min_length=1, max_length=64)
    type: str = Field(max_length=64)
    data: InvoiceData


# Estado novo -> estados de origem permitidos (evita regressões com eventos
# fora de ordem, ex.: "failed" chegando depois de "paid").
EVENT_TO_STATUS = {
    EventType.INVOICE_PAID: InvoiceStatus.PAID,
    EventType.INVOICE_PAYMENT_FAILED: InvoiceStatus.FAILED,
    EventType.INVOICE_CANCELED: InvoiceStatus.CANCELED,
    EventType.INVOICE_REFUNDED: InvoiceStatus.REFUNDED,
}
ALLOWED_TRANSITIONS = {
    InvoiceStatus.PAID: {InvoiceStatus.PENDING, InvoiceStatus.FAILED},
    InvoiceStatus.FAILED: {InvoiceStatus.PENDING},
    InvoiceStatus.CANCELED: {InvoiceStatus.PENDING, InvoiceStatus.FAILED},
    InvoiceStatus.REFUNDED: {InvoiceStatus.PAID},
}


# --------------------------------------------------------------------------
# Verificação de assinatura
# Cabeçalho esperado: "t=<unix_ts>,v1=<hex_hmac>"; HMAC sobre f"{t}.{corpo}"
# --------------------------------------------------------------------------
def verify_signature(raw_body: bytes, header: str | None) -> None:
    if not header:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Assinatura ausente")
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        timestamp = int(parts["t"])
        received_sig = parts["v1"]
    except (ValueError, KeyError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Assinatura malformada")

    if abs(time.time() - timestamp) > SIGNATURE_TOLERANCE_SECONDS:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Timestamp fora da janela")

    signed = f"{timestamp}.".encode() + raw_body
    expected = hmac.new(WEBHOOK_SECRET, signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, received_sig):  # tempo constante
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Assinatura inválida")


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
@router.post("/payments", status_code=status.HTTP_200_OK)
async def payment_webhook(
    request: Request,
    x_gateway_signature: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    # 1) Corpo bruto, com limite de tamanho
    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Corpo muito grande")

    # 2) Autenticidade ANTES de qualquer parsing ou acesso ao banco
    verify_signature(raw_body, x_gateway_signature)

    # 3) Parsing/validação
    try:
        payload = WebhookPayload.model_validate_json(raw_body)
    except ValidationError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Payload inválido")

    try:
        event_type = EventType(payload.type)
    except ValueError:
        # Evento que não tratamos: 200 para o gateway não ficar reenviando.
        logger.info("Evento ignorado: %s", payload.type)
        return {"status": "ignored"}

    new_status = EVENT_TO_STATUS[event_type]
    now = datetime.now(timezone.utc)

    try:
        # 4) Idempotência: o INSERT com unique falha se o evento já foi processado
        db.add(WebhookEvent(
            gateway_event_id=payload.event_id,
            event_type=payload.type,
            received_at=now,
        ))
        db.flush()

        # 5) Localiza a fatura pelo ID do gateway e trava a linha (evita corrida
        #    entre entregas concorrentes do mesmo pagamento)
        invoice = db.execute(
            select(Invoice)
            .where(Invoice.gateway_invoice_id == payload.data.invoice_id)
            .with_for_update()
        ).scalar_one_or_none()

        if invoice is None:
            db.commit()  # registra o evento; nada a atualizar
            logger.warning("Fatura desconhecida: %s", payload.data.invoice_id)
            return {"status": "invoice_not_found"}

        # 6) Isolamento entre tenants: o cliente informado pelo gateway precisa
        #    pertencer à empresa dona da fatura.
        company = db.get(Company, invoice.company_id)
        if company is None or company.gateway_customer_id != payload.data.customer_id:
            db.rollback()
            logger.error(
                "Divergência de tenant: invoice=%s company=%s",
                invoice.id, invoice.company_id,
            )
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Cliente divergente")

        # 7) Integridade financeira: valor confirmado deve bater com a fatura
        if event_type is EventType.INVOICE_PAID and payload.data.amount_cents != invoice.amount_cents:
            db.rollback()
            logger.error("Valor divergente: invoice=%s", invoice.id)
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Valor divergente")

        # 8) Máquina de estados
        current = InvoiceStatus(invoice.status)
        if current == new_status:
            db.commit()
            return {"status": "already_applied"}
        if current not in ALLOWED_TRANSITIONS[new_status]:
            db.commit()
            logger.info("Transição ignorada: %s -> %s (invoice=%s)", current, new_status, invoice.id)
            return {"status": "transition_ignored"}

        invoice.status = new_status.value
        invoice.updated_at = now
        if new_status is InvoiceStatus.PAID:
            invoice.paid_at = now

        db.commit()  # evento + fatura na mesma transação
        return {"status": "ok"}

    except IntegrityError:
        db.rollback()
        # event_id duplicado -> já processado; responde 200 (idempotente)
        return {"status": "duplicate"}
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        logger.exception("Falha ao processar webhook event_id=%s", payload.event_id)
        # 5xx faz o gateway tentar novamente mais tarde
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Erro interno")