import enum
from datetime import datetime
from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Numeric,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class InvoiceStatus(str, enum.Enum):
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    CANCELED = "canceled"


class SubscriptionStatus(str, enum.Enum):
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    INCOMPLETE = "incomplete"


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String(36), primary_key=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    gateway_subscription_id = Column(String(100), unique=True, nullable=True)
    status = Column(Enum(SubscriptionStatus), default=SubscriptionStatus.ACTIVE, nullable=False)
    current_period_end = Column(DateTime, nullable=True)


class Invoice(Base):
    __tablename__ = "invoices"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    subscription_id = Column(String(36), ForeignKey("subscriptions.id"), nullable=False)
    gateway_invoice_id = Column(String(100), unique=True, nullable=False, index=True)
    amount = Column(Numeric(10, 2), nullable=False)
    status = Column(Enum(InvoiceStatus), default=InvoiceStatus.PENDING, nullable=False)
    paid_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Restringe unicidade composta garantindo isolamento
    __table_args__ = (
        UniqueConstraint("id", "tenant_id", name="uq_invoice_tenant"),
    )


class ProcessedWebhookEvent(Base):
    """Garante idempotência estrita para mitigar processamento duplicado."""
    __tablename__ = "processed_webhook_events"

    event_id = Column(String(100), primary_key=True)
    event_type = Column(String(100), nullable=False)
    processed_at = Column(DateTime, default=datetime.utcnow, nullable=False)

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class GatewayEventPayload(BaseModel):
    id: str = Field(..., min_length=5, max_length=100)
    type: str = Field(..., min_length=3, max_length=100)
    data: Dict[str, Any]

    class Config:
        extra = "ignore"

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

# Configuração de logger seguro (sem dados de cartão ou payloads brutos sensíveis)
logger = logging.getLogger("security_audit")
router = APIRouter(prefix="/api/v1/webhooks", tags=["Webhooks"])

WEBHOOK_SECRET = os.getenv("GATEWAY_WEBHOOK_SECRET", "super-secret-gateway-signing-key")


def get_db():
    """Dependência para injeção de sessão do banco de dados."""
    # Substituir pela sua engine/sessionmaker real
    db = Session()
    try:
        yield db
    finally:
        db.close()


def verify_hmac_signature(raw_body: bytes, signature_header: Optional[str]) -> bool:
    """Valida a integridade da requisição contra o segredo compartilhado."""
    if not signature_header or not WEBHOOK_SECRET:
        return False

    expected_signature = hmac.new(
        key=WEBHOOK_SECRET.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256
    ).hexdigest()

    # Mitigação contra Timing Attacks (OWASP A02/A07)
    return hmac.compare_digest(expected_signature, signature_header)


@router.post(
    "/payment-gateway",
    status_code=status.HTTP_200_OK,
    summary="Recebe notificações assíncronas do Gateway de Pagamento")
async def handle_payment_gateway_webhook(
    request: Request,
    x_signature: Optional[str] = Header(None, alias="X-Signature-SHA256"),
    db: Session = Depends(get_db)):
    # 1. Leitura do corpo bruto para verificação criptográfica estrita
    raw_body = await request.body()
    if not verify_hmac_signature(raw_body, x_signature):
        logger.warning("Falha de autenticação no webhook: assinatura inválida ou ausente.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Assinatura de requisição inválida."
        )

    # 2. Deserialização segura do JSON
    try:
        payload_data = json.loads(raw_body.decode("utf-8"))
        event = GatewayEventPayload(**payload_data)
    except Exception as exc:
        logger.error(f"Payload do webhook malformado: {str(exc)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload inválido."
        )

    # 3. Idempotência: Checa se o evento já foi processado
    existing_event = db.query(ProcessedWebhookEvent).filter_by(event_id=event.id).first()
    if existing_event:
        logger.info(f"Evento {event.id} já processado anteriormente. Ignorando reenvio.")
        return {"status": "ignored", "reason": "already_processed"}

    # 4. Transação atômica para processamento de eventos
    try:
        gateway_invoice_id = event.data.get("object", {}).get("id")
        if not gateway_invoice_id:
            logger.warning(f"Evento {event.id} recebido sem identificador de fatura no objeto.")
            return {"status": "ignored", "reason": "missing_invoice_reference"}

        # OWASP A01: A busca é atrelada estritamente aos relacionamentos internos da base
        invoice = (
            db.query(Invoice)
            .filter(Invoice.gateway_invoice_id == gateway_invoice_id)
            .with_for_update()  # Lock pessimista contra race conditions
            .first()
        )

        if not invoice:
            logger.warning(
                f"Fatura {gateway_invoice_id} não encontrada para o evento {event.id}."
            )
            # Retorna 200 para o gateway não reenviar infinitamente dados inexistentes
            return {"status": "ignored", "reason": "invoice_not_found"}

        subscription = (
            db.query(Subscription)
            .filter(
                Subscription.id == invoice.subscription_id,
                Subscription.tenant_id == invoice.tenant_id  # Validação de isolamento do tenant
            )
            .first()
        )

        # 5. Tratamento de máquina de estados
        if event.type == "invoice.payment_succeeded":
            invoice.status = InvoiceStatus.PAID
            invoice.paid_at = datetime.utcnow()

            if subscription:
                subscription.status = SubscriptionStatus.ACTIVE
                # Atualiza vigência se enviado pelo gateway
                period_end_timestamp = event.data.get("object", {}).get("current_period_end")
                if period_end_timestamp:
                    subscription.current_period_end = datetime.utcfromtimestamp(period_end_timestamp)

            logger.info(
                f"Fatura {invoice.id} paga com sucesso para o tenant {invoice.tenant_id}."
            )

        elif event.type == "invoice.payment_failed":
            invoice.status = InvoiceStatus.FAILED

            if subscription:
                subscription.status = SubscriptionStatus.PAST_DUE

            logger.warning(
                f"Pagamento da fatura {invoice.id} falhou para o tenant {invoice.tenant_id}."
            )

        elif event.type == "invoice.canceled":
            invoice.status = InvoiceStatus.CANCELED
            logger.info(f"Fatura {invoice.id} cancelada para o tenant {invoice.tenant_id}.")

        # Registra o evento para garantir idempotência nas próximas chamadas
        processed_marker = ProcessedWebhookEvent(
            event_id=event.id,
            event_type=event.type,
            processed_at=datetime.utcnow()
        )
        db.add(processed_marker)
        db.commit()

    except Exception as exc:
        db.rollback()
        logger.error(
            f"Erro ao persistir transação do webhook para evento {event.id}: {str(exc)}",
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao processar evento."
        )

    return {"status": "success", "event_id": event.id}