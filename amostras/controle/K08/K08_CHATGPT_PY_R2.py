from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import json
import os

from fastapi import FastAPI, Header, HTTPException, Request, status
from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ["DATABASE_URL"]
WEBHOOK_SECRET = os.environ["PAYMENT_WEBHOOK_SECRET"]

MAX_WEBHOOK_SIZE = 64 * 1024  # 64 KiB


# ---------------------------------------------------------------------------
# Banco
# ---------------------------------------------------------------------------

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)


class Base(DeclarativeBase):
    pass


class InvoiceStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    CANCELED = "canceled"


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)


class Invoice(Base):
    __tablename__ = "invoices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # O tenant é determinado pelo registro da própria fatura.
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"),
        nullable=False,
        index=True,
    )

    # ID da fatura no gateway.
    external_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    status: Mapped[InvoiceStatus] = mapped_column(
        SAEnum(InvoiceStatus),
        nullable=False,
        default=InvoiceStatus.PENDING,
    )

    paid_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Evita que duas faturas internas sejam associadas ao mesmo
    # identificador externo.
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "external_id",
            name="uq_invoice_tenant_external_id",
        ),
    )


class WebhookEvent(Base):
    """
    Registro de eventos já processados.

    Serve para idempotência e também para auditoria.
    """

    __tablename__ = "webhook_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    event_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
    )

    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


# ---------------------------------------------------------------------------
# Aplicação
# ---------------------------------------------------------------------------

app = FastAPI()


# ---------------------------------------------------------------------------
# Autenticação do webhook
# ---------------------------------------------------------------------------

def verify_signature(payload: bytes, signature: str) -> bool:
    """
    Exemplo de assinatura HMAC-SHA256.

    O formato esperado do header é:

        X-Payment-Signature: sha256=<hex>

    O formato exato deve ser adaptado à documentação do gateway.
    """

    prefix = "sha256="

    if not signature.startswith(prefix):
        return False

    received_signature = signature[len(prefix):]

    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        received_signature,
        expected_signature,
    )


# ---------------------------------------------------------------------------
# Validação do evento
# ---------------------------------------------------------------------------

ALLOWED_EVENTS = {
    "invoice.paid",
    "invoice.payment_failed",
    "invoice.canceled",
}


def parse_event(payload: bytes) -> dict:
    try:
        event = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid webhook payload",
        )

    if not isinstance(event, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid webhook format",
        )

    event_id = event.get("id")
    event_type = event.get("type")
    data = event.get("data")

    if not isinstance(event_id, str) or not event_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing event id",
        )

    if event_type not in ALLOWED_EVENTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported event type",
        )

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid event data",
        )

    external_invoice_id = data.get("invoice_id")

    if not isinstance(external_invoice_id, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing invoice id",
        )

    return {
        "id": event_id,
        "type": event_type,
        "invoice_id": external_invoice_id,
    }


# ---------------------------------------------------------------------------
# Mapeamento de estados
# ---------------------------------------------------------------------------

def map_invoice_status(event_type: str) -> InvoiceStatus:
    mapping = {
        "invoice.paid": InvoiceStatus.PAID,
        "invoice.payment_failed": InvoiceStatus.FAILED,
        "invoice.canceled": InvoiceStatus.CANCELED,
    }

    return mapping[event_type]


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------

@app.post("/webhooks/payment", status_code=status.HTTP_204_NO_CONTENT)
async def payment_webhook(
    request: Request,
    x_payment_signature: str = Header(...),
):
    # 1. Limite explícito contra payloads excessivamente grandes.
    content_length = request.headers.get("content-length")

    if content_length is not None:
        try:
            if int(content_length) > MAX_WEBHOOK_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="Payload too large",
                )
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Content-Length",
            )

    payload = await request.body()

    if len(payload) > MAX_WEBHOOK_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload too large",
        )

    # 2. Autenticar o gateway ANTES de confiar no conteúdo.
    if not verify_signature(payload, x_payment_signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    # 3. Interpretar e validar o evento.
    event = parse_event(payload)

    event_id = event["id"]
    event_type = event["type"]
    external_invoice_id = event["invoice_id"]

    new_status = map_invoice_status(event_type)

    # 4. Transação única para garantir idempotência + atualização.
    with Session(engine) as session:
        try:
            # O INSERT é protegido por UNIQUE(event_id).
            #
            # Em produção, pode-se usar INSERT ... ON CONFLICT DO NOTHING
            # específico para o banco utilizado.
            webhook_event = WebhookEvent(
                event_id=event_id,
                received_at=datetime.now(timezone.utc),
            )

            session.add(webhook_event)

            try:
                session.flush()
            except Exception:
                session.rollback()

                # Evento já processado.
                existing = session.scalar(
                    select(WebhookEvent).where(
                        WebhookEvent.event_id == event_id
                    )
                )

                if existing is not None:
                    return

                raise

            # 5. Localização da fatura.
            #
            # IMPORTANTE:
            # não usamos tenant_id fornecido pelo cliente/gateway.
            #
            # O external_invoice_id já foi associado anteriormente
            # à fatura interna.
            invoice = session.scalar(
                select(Invoice)
                .where(
                    Invoice.external_id == external_invoice_id
                )
                .with_for_update()
            )

            if invoice is None:
                # Não revelar detalhes internos da base.
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Invoice not found",
                )

            # 6. Transições permitidas.
            #
            # Não permitimos, por exemplo, que uma fatura paga volte
            # silenciosamente para pending.
            if invoice.status == InvoiceStatus.PAID:
                session.commit()
                return

            invoice.status = new_status

            if new_status == InvoiceStatus.PAID:
                invoice.paid_at = datetime.now(timezone.utc)

            session.commit()

        except HTTPException:
            session.rollback()
            raise

        except Exception:
            session.rollback()

            # Não retornar stack trace nem detalhes internos.
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Webhook processing failed",
            )

    return
