import hmac
import hashlib
import os
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from fastapi import FastAPI, APIRouter, Request, Header, HTTPException, status, Depends
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Numeric, DateTime, ForeignKey, Index
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# Configuração de Logs Seguros (OWASP A09)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("webhook_billing")

WEBHOOK_SECRET = os.getenv("GATEWAY_WEBHOOK_SECRET", "super-secret-gateway-signing-key").encode("utf-8")

Base = declarative_base()

# --- MODELOS DE DADOS ---

class InvoiceStatus(str, Enum):
    PENDING = "PENDING"
    PAID = "PAID"
    FAILED = "FAILED"
    REFUNDED = "REFUNDED"

class Invoice(Base):
    """
    Tabela particionada logicamente por tenant_id.
    O gateway_transaction_id garante a rastreabilidade do webhook.
    """
    __tablename__ = "invoices"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(36), nullable=False, index=True)  # UUID da empresa cliente
    amount = Column(Numeric(10, 2), nullable=False)
    status = Column(String(20), nullable=False, default=InvoiceStatus.PENDING)
    gateway_transaction_id = Column(String(100), unique=True, nullable=True, index=True)
    paid_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_invoices_tenant_id_id", "tenant_id", "id"),
    )

class ProcessedWebhookEvent(Base):
    """
    Garante idempotência (OWASP A04/A08):
    Impede ataques de replay e duplicação de processamento pelo gateway.
    """
    __tablename__ = "processed_webhook_events"

    event_id = Column(String(100), primary_key=True)
    processed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# --- ESQUEMAS DE ENTRADA (OWASP A03 / Validação Estrita) ---

class WebhookPayloadData(BaseModel):
    transaction_id: str = Field(..., max_length=100)
    invoice_id: int
    tenant_id: str = Field(..., max_length=36)
    status: InvoiceStatus

class GatewayWebhookEvent(BaseModel):
    event_id: str = Field(..., max_length=100)
    event_type: str = Field(..., max_length=50)
    data: WebhookPayloadData


# --- INICIALIZAÇÃO DA APLICAÇÃO ---

app = FastAPI()
router = APIRouter()

# Setup de banco de dados (exemplo com SQLite/Postgres)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./saas.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- VALIDAÇÃO CRIPTOGRÁFICA (OWASP A02) ---

def verify_hmac_signature(raw_body: bytes, signature_header: Optional[str]) -> None:
    """
    Verifica a autenticidade e integridade do payload usando HMAC-SHA256.
    Protegido contra Timing Attacks com hmac.compare_digest.
    """
    if not signature_header:
        logger.warning("Tentativa de webhook sem assinatura.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Assinatura ausente."
        )

    expected_signature = hmac.new(WEBHOOK_SECRET, raw_body, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_signature, signature_header):
        logger.warning("Falha na validação de assinatura do webhook.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Assinatura inválida."
        )


# --- ROTA DE WEBHOOK ---

@router.post("/webhooks/payment-gateway", status_code=status.HTTP_200_OK)
async def handle_payment_webhook(
    request: Request,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    db: Session = Depends(get_db)):
    # 1. Leitura do corpo bruto (bytes) para validação HMAC antes do parsing
    raw_body = await request.body()
    verify_hmac_signature(raw_body, x_signature)

    # 2. Parsing e Validação de Esquema
    try:
        payload = GatewayWebhookEvent.model_validate_json(raw_body)
    except Exception as exc:
        logger.error("Payload do webhook malformado: %s", str(exc))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Formato de carga inválido."
        )

    # 3. Transação Atômica e Isolamento
    try:
        # A. Idempotência: Checa se o evento já foi processado
        existing_event = db.query(ProcessedWebhookEvent).filter_by(
            event_id=payload.event_id
        ).first()

        if existing_event:
            logger.info("Evento %s já processado anteriormente. Ignorando.", payload.event_id)
            return {"status": "success", "message": "Evento já registrado anteriormente."}

        # B. Controle de Acesso e Isolamento Multilocatário (OWASP A01)
        # O filtro DEVE conter obrigatoriamente tanto o id quanto o tenant_id.
        invoice_query = db.query(Invoice).filter(
            Invoice.id == payload.data.invoice_id,
            Invoice.tenant_id == payload.data.tenant_id
        )

        # with_for_update(): Bloqueio pessimista para evitar Race Conditions (OWASP A04)
        invoice = invoice_query.with_for_update().first()

        if not invoice:
            # Não expor detalhes de banco; registrar no log de auditoria interno
            logger.warning(
                "Fatura ID %s não encontrada para o Tenant ID %s.",
                payload.data.invoice_id, payload.data.tenant_id
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Registro de cobrança não localizado para o locatário informado."
            )

        # C. Transição de Estado Segura
        if invoice.status == InvoiceStatus.PAID and payload.data.status == InvoiceStatus.PAID:
            logger.info("Fatura ID %s já está marcada como PAGA.", invoice.id)
        else:
            invoice.status = payload.data.status
            invoice.gateway_transaction_id = payload.data.transaction_id

            if payload.data.status == InvoiceStatus.PAID:
                invoice.paid_at = datetime.now(timezone.utc)

        # D. Registrar consumo do evento para idempotência
        db.add(ProcessedWebhookEvent(event_id=payload.event_id))

        db.commit()

        logger.info(
            "Fatura %s (Tenant: %s) atualizada com sucesso para %s.",
            invoice.id, invoice.tenant_id, invoice.status
        )
        return {"status": "success"}

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.exception("Erro inesperado no processamento do webhook: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha interna no processamento do evento."
        )

app.include_router(router)