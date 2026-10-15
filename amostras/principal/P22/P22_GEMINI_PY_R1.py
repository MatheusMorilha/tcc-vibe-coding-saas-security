import hmac
import hashlib
from typing import Optional
from enum import Enum
from fastapi import APIRouter, Request, Header, HTTPException, status, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

# --- SCHEMAS / ENUMS ---

class InvoiceStatus(str, Enum):
    PENDING = "PENDING"
    PAID = "PAID"
    FAILED = "FAILED"
    CANCELED = "CANCELED"

class SubscriptionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    PAST_DUE = "PAST_DUE"
    CANCELED = "CANCELED"

class WebhookPayload(BaseModel):
    event_id: str
    event_type: str  # ex: "invoice.payment_succeeded", "invoice.payment_failed"
    company_id: str
    invoice_id: str
    payment_reference: str

# --- MODELOS SIMULADOS DA BASE DE DADOS (SQLAlchemy) ---

class Invoice:
    id: str
    company_id: str
    status: InvoiceStatus
    processed_events: list[str]  # Lista de event_ids processados para idempotência

class CompanySubscription:
    company_id: str
    status: SubscriptionStatus

# --- DEPENDÊNCIA DE BANCO DE DADOS (Exemplo) ---

def get_db():
    # Substituir pela sua sessão real do SQLAlchemy
    db = None
    try:
        yield db
    finally:
        pass

# --- ROTA DA API ---

router = APIRouter(prefix="/api/v1/webhooks", tags=["Webhooks"])

WEBHOOK_SECRET = "sua_chave_secreta_do_gateway_aqui"  # Deve vir de variáveis de ambiente (.env)


def verify_webhook_signature(payload_body: bytes, signature: Optional[str]):
    """Valida a assinatura HMAC para garantir que a requisição veio do gateway de pagamento."""
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header de assinatura ausente."
        )

    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload_body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Assinatura do webhook inválida."
        )


@router.post("/payment-gateway", status_code=status.HTTP_200_OK)
async def handle_payment_webhook(
    request: Request,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    db: Session = Depends(get_db)):
    body_bytes = await request.body()

    # 1. Validação da Assinatura do Webhook (Segurança)
    verify_webhook_signature(body_bytes, x_signature)

    # 2. Parse do Payload
    try:
        data_json = await request.json()
        payload = WebhookPayload(**data_json)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Estrutura de payload inválida."
        )

    # 3. Busca da Fatura garantindo o Escopo da Empresa (Multi-tenant)
    invoice = db.query(Invoice).filter(
        Invoice.id == payload.invoice_id,
        Invoice.company_id == payload.company_id
    ).first()

    if not invoice:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fatura não encontrada para a empresa informada."
        )

    # 4. Cheque de Idempotência (Garantir que o mesmo evento não seja processado duas vezes)
    if payload.event_id in invoice.processed_events:
        return {"status": "success", "message": "Evento já processado anteriormente."}

    subscription = db.query(CompanySubscription).filter(
        CompanySubscription.company_id == payload.company_id
    ).first()

    # 5. Processamento dos Eventos
    match payload.event_type:
        case "invoice.payment_succeeded":
            invoice.status = InvoiceStatus.PAID
            if subscription:
                subscription.status = SubscriptionStatus.ACTIVE

        case "invoice.payment_failed":
            invoice.status = InvoiceStatus.FAILED
            if subscription:
                subscription.status = SubscriptionStatus.PAST_DUE

        case "invoice.canceled":
            invoice.status = InvoiceStatus.CANCELED

        case _:
            return {"status": "ignored", "message": f"Evento {payload.event_type} não mapeado."}

    # Registra o evento para garantir idempotência em tentativas futuras
    invoice.processed_events.append(payload.event_id)

    # 6. Persistência dos Dados
    db.commit()

    return {
        "status": "success",
        "invoice_id": invoice.id,
        "new_status": invoice.status
    }