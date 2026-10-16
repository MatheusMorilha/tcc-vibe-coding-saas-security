import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Numeric, Enum, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class InvoiceStatus(str, enum.Enum):
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    CANCELED = "canceled"

class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)

class Invoice(Base):
    __tablename__ = "invoices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Isolamento de locatário obrigatório
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True)
    gateway_invoice_id = Column(String(100), nullable=False, unique=True, index=True)
    amount = Column(Numeric(10, 2), nullable=False)
    status = Column(Enum(InvoiceStatus), nullable=False, default=InvoiceStatus.PENDING)
    paid_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class ProcessedWebhookEvent(Base):
    """Garante idempotência e previne ataques de replay."""
    __tablename__ = "processed_webhook_events"

    event_id = Column(String(100), primary_key=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=True)
    processed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

from pydantic import BaseModel, Field
from typing import Literal

class WebhookData(BaseModel):
    gateway_invoice_id: str = Field(..., min_length=1, max_length=100)
    status: Literal["payment_succeeded", "payment_failed", "invoice_canceled"]

class PaymentWebhookPayload(BaseModel):
    event_id: str = Field(..., min_length=1, max_length=100)
    event_type: str = Field(..., min_length=1, max_length=50)
    data: WebhookData

import hmac
import hashlib
import os
import logging
from datetime import datetime, timezone
from fastapi import FastAPI, Request, Header, HTTPException, status, Depends
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from models import Base, Invoice, InvoiceStatus, ProcessedWebhookEvent
from schemas import PaymentWebhookPayload

logger = logging.getLogger("security_audit")
logger.setLevel(logging.INFO)

app = FastAPI()

# Carregado via secrets/variáveis de ambiente seguras (A05: Security Misconfiguration)
WEBHOOK_SECRET = os.getenv("PAYMENT_GATEWAY_WEBHOOK_SECRET", "")

def get_db():
    # Simulação da injeção de dependência da sessão de banco
    # yield session
    ...

def verify_webhook_signature(payload_bytes: bytes, signature_header: str | None) -> None:
    """Validação da assinatura digital via HMAC-SHA256 (A02 & A08)."""
    if not WEBHOOK_SECRET or not signature_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticação do webhook ausente ou inválida."
        )

    expected_signature = hmac.new(
        key=WEBHOOK_SECRET.encode("utf-8"),
        msg=payload_bytes,
        digestmod=hashlib.sha256
    ).hexdigest()

    # Comparação em tempo constante para mitigar timing attacks
    if not hmac.compare_digest(expected_signature, signature_header):
        logger.warning("Falha na validação de assinatura do webhook.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Assinatura inválida."
        )

@app.post("/api/v1/webhooks/payments", status_code=status.HTTP_200_OK)
async def handle_payment_webhook(
    request: Request,
    x_signature: str | None = Header(default=None, alias="X-Signature-SHA256"),
    db: Session = Depends(get_db)):
    # 1. Leitura do corpo bruto (Raw Body) para validação exata da assinatura
    raw_body = await request.body()
    verify_webhook_signature(raw_body, x_signature)

    # 2. Deserialização e validação estrutural contra esquemas tipados
    try:
        body_json = await request.json()
        payload = PaymentWebhookPayload.model_validate(body_json)
    except Exception as exc:
        logger.error("Payload malformado recebido no webhook: %s", str(exc))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Payload inválido."
        )

    # 3. Tratamento de Idempotência dentro de transação segura
    try:
        with db.begin():
            # Verifica se o evento já foi processado anteriormente
            event_exists = db.query(ProcessedWebhookEvent).filter_by(
                event_id=payload.event_id
            ).first()

            if event_exists:
                # Retorna 200 para evitar que o gateway continue tentando reenviar
                return {"status": "success", "message": "Evento já processado anteriormente."}

            # 4. Busca da fatura com consulta parametrizada via gateway_invoice_id
            invoice = db.query(Invoice).filter(
                Invoice.gateway_invoice_id == payload.data.gateway_invoice_id
            ).with_for_update().first()

            if not invoice:
                # Registra o evento para auditoria mesmo sem fatura encontrada
                logger.warning(
                    "Fatura %s não encontrada para o evento %s",
                    payload.data.gateway_invoice_id,
                    payload.event_id
                )
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Fatura não localizada."
                )

            # 5. Mapeamento de estado e atualização segura respeitando o tenant_id da entidade
            now = datetime.now(timezone.utc)
            event_status = payload.data.status

            if event_status == "payment_succeeded":
                invoice.status = InvoiceStatus.PAID
                invoice.paid_at = now
            elif event_status == "payment_failed":
                invoice.status = InvoiceStatus.FAILED
            elif event_status == "invoice_canceled":
                invoice.status = InvoiceStatus.CANCELED

            invoice.updated_at = now

            # 6. Registra o evento como concluído com o tenant_id correspondente
            db.add(ProcessedWebhookEvent(
                event_id=payload.event_id,
                tenant_id=invoice.tenant_id
            ))

    except IntegrityError as err:
        logger.error("Erro de concorrência ou integridade relacional: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Conflito de processamento concorrente."
        )

    logger.info(
        "Fatura %s (Tenant: %s) atualizada para %s com sucesso.",
        invoice.id,
        invoice.tenant_id,
        invoice.status
    )

    return {"status": "success", "invoice_id": str(invoice.id)}