"""
Rota de webhook para notificações do gateway de pagamento.

Formato assumido (adaptar ao gateway real):
  Cabeçalho:  X-Gateway-Signature: t=<unix_ts>,v1=<hex_hmac_sha256>
  Assinado:   f"{t}.".encode() + corpo_bruto
  Corpo JSON: {"event_id": "...", "type": "invoice.paid",
               "data": {"invoice_id": "...", "amount_cents": 12900, "currency": "BRL"}}

Variáveis de ambiente:
  DATABASE_URL                 ex.: postgresql+psycopg://user:pass@host/db
  GATEWAY_WEBHOOK_SECRETS      segredos separados por vírgula (suporta rotação)
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import (
    BigInteger, DateTime, ForeignKey, String, UniqueConstraint, create_engine, select,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

log = logging.getLogger("billing.webhook")

# --------------------------------------------------------------------------
# Configuração (A05 - Security Misconfiguration: falha fechada se faltar segredo)
# --------------------------------------------------------------------------
_RAW_SECRETS = os.environ.get("GATEWAY_WEBHOOK_SECRETS", "")
WEBHOOK_SECRETS: list[bytes] = [s.strip().encode() for s in _RAW_SECRETS.split(",") if s.strip()]
if not WEBHOOK_SECRETS:
    raise RuntimeError("GATEWAY_WEBHOOK_SECRETS não configurado")

MAX_BODY_BYTES = 64 * 1024        # limita payload (mitiga DoS)
TIMESTAMP_TOLERANCE_S = 300       # janela anti-replay

engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def get_db():
    with SessionLocal() as session:
        yield session


# --------------------------------------------------------------------------
# Modelos
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class InvoiceStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    CANCELED = "canceled"
    EXPIRED = "expired"
    REFUNDED = "refunded"


class Invoice(Base):
    __tablename__ = "invoices"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    gateway_invoice_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    amount_cents: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3))
    status: Mapped[str] = mapped_column(String(16), default=InvoiceStatus.PENDING.value)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class WebhookEvent(Base):
    """Registro de eventos processados -> idempotência e trilha de auditoria."""
    __tablename__ = "webhook_events"
    __table_args__ = (UniqueConstraint("event_id", name="uq_webhook_event_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(64))
    tenant_id: Mapped[int | None] = mapped_column(nullable=True)
    invoice_id: Mapped[int | None] = mapped_column(nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------
# Validação estrita do payload (A03 - Injection / A08 - Integrity)
# --------------------------------------------------------------------------
class InvoiceData(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    invoice_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")
    amount_cents: int = Field(ge=0, le=10**12)
    currency: str = Field(min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")


class WebhookPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_\-\.]+$")
    type: Literal["invoice.paid", "invoice.payment_failed", "invoice.canceled",
                  "invoice.expired", "invoice.refunded"]
    data: InvoiceData


EVENT_TO_STATUS = {
    "invoice.paid": InvoiceStatus.PAID,
    "invoice.payment_failed": InvoiceStatus.FAILED,
    "invoice.canceled": InvoiceStatus.CANCELED,
    "invoice.expired": InvoiceStatus.EXPIRED,
    "invoice.refunded": InvoiceStatus.REFUNDED,
}

# Máquina de estados: impede regressões (ex.: paid -> pending) e eventos fora de ordem.
ALLOWED_TRANSITIONS: dict[InvoiceStatus, set[InvoiceStatus]] = {
    InvoiceStatus.PENDING: {InvoiceStatus.PAID, InvoiceStatus.FAILED,
                            InvoiceStatus.CANCELED, InvoiceStatus.EXPIRED},
    InvoiceStatus.FAILED: {InvoiceStatus.PAID, InvoiceStatus.CANCELED, InvoiceStatus.EXPIRED},
    InvoiceStatus.PAID: {InvoiceStatus.REFUNDED},
    InvoiceStatus.CANCELED: set(),
    InvoiceStatus.EXPIRED: set(),
    InvoiceStatus.REFUNDED: set(),
}


# --------------------------------------------------------------------------
# Autenticidade da mensagem (A07 - Authentication Failures / A02 - Crypto)
# --------------------------------------------------------------------------
def _verify_signature(header: str | None, body: bytes) -> None:
    """Valida HMAC sobre o corpo BRUTO + timestamp. Lança 401 genérico em qualquer falha."""
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid signature")
    if not header or len(header) > 512:
        raise unauthorized

    try:
        parts = dict(item.split("=", 1) for item in header.split(","))
        ts = int(parts["t"])
        received_sig = parts["v1"]
    except (ValueError, KeyError):
        raise unauthorized

    # Anti-replay
    if abs(time.time() - ts) > TIMESTAMP_TOLERANCE_S:
        raise unauthorized

    signed = f"{ts}.".encode() + body
    # Compara em tempo constante contra cada segredo ativo (rotação de chaves)
    valid = False
    for secret in WEBHOOK_SECRETS:
        expected = hmac.new(secret, signed, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, received_sig):
            valid = True
    if not valid:
        raise unauthorized


async def _read_limited_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "payload too large")

    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "payload too large")
        chunks.append(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
router = APIRouter()


@router.post("/webhooks/payments", status_code=status.HTTP_200_OK, include_in_schema=False)
async def payment_webhook(request: Request, db: Session = Depends(get_db)) -> dict:
    # 1) Corpo bruto limitado + verificação de assinatura ANTES de qualquer parsing
    body = await _read_limited_body(request)
    _verify_signature(request.headers.get("x-gateway-signature"), body)

    # 2) Parsing e validação estrita
    try:
        payload = WebhookPayload.model_validate_json(body)
    except ValidationError:
        # Mensagem autêntica mas inválida: 400 sem detalhes internos
        log.warning("webhook payload inválido (assinatura ok)")
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid payload")

    target_status = EVENT_TO_STATUS[payload.type]
    now = datetime.now(timezone.utc)

    try:
        with db.begin():  # transação única: evento + fatura são atômicos
            # 3) Localiza a fatura com lock; o tenant vem do REGISTRO, nunca do payload
            invoice = db.execute(
                select(Invoice)
                .where(Invoice.gateway_invoice_id == payload.data.invoice_id)
                .with_for_update()
            ).scalar_one_or_none()

            if invoice is None:
                # Não revela existência; 200 evita retries infinitos para ids desconhecidos
                log.warning("webhook para fatura desconhecida event_id=%s", payload.event_id)
                return {"status": "ignored"}

            # 4) Idempotência: UNIQUE(event_id) rejeita reentrega do mesmo evento
            db.add(WebhookEvent(
                event_id=payload.event_id, event_type=payload.type,
                tenant_id=invoice.tenant_id, invoice_id=invoice.id, received_at=now,
            ))
            try:
                db.flush()
            except IntegrityError:
                db.rollback()
                return {"status": "duplicate"}

            # 5) Integridade financeira: valor e moeda devem bater com a fatura
            if (payload.data.amount_cents != invoice.amount_cents
                    or payload.data.currency != invoice.currency):
                log.critical(
                    "DIVERGÊNCIA de valor/moeda tenant=%s invoice=%s event_id=%s",
                    invoice.tenant_id, invoice.id, payload.event_id,
                )
                return {"status": "ignored"}

            # 6) Transição de estado válida?
            current = InvoiceStatus(invoice.status)
            if current == target_status:
                return {"status": "noop"}
            if target_status not in ALLOWED_TRANSITIONS[current]:
                log.warning(
                    "transição inválida %s->%s tenant=%s invoice=%s",
                    current.value, target_status.value, invoice.tenant_id, invoice.id,
                )
                return {"status": "ignored"}

            invoice.status = target_status.value
            invoice.updated_at = now
            if target_status is InvoiceStatus.PAID:
                invoice.paid_at = now

            log.info(
                "fatura atualizada tenant=%s invoice=%s %s->%s event_id=%s",
                invoice.tenant_id, invoice.id, current.value, target_status.value,
                payload.event_id,
            )
    except SQLAlchemyError:
        # Falha transitória: 500 genérico para o gateway reenviar (sem vazar detalhes)
        log.exception("erro de banco ao processar webhook event_id=%s", payload.event_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "internal error")

    return {"status": "processed"}


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # A05: sem docs expostas
app.include_router(router)