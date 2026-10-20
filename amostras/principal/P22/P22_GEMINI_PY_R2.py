import hmac
import hashlib
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, status, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Configuração simulada do Banco de Dados (Multitenant com coluna tenant_id)
DATABASE_URL = "postgresql://user:password@localhost/saas_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class InvoiceModel(Base):
    __tablename__ = "invoices"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, index=True, nullable=False)
    gateway_invoice_id = Column(String, unique=True, index=True, nullable=False)
    status = Column(String, nullable=False) # pending, paid, failed, cancelled
    amount = Column(Integer, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SubscriptionModel(Base):
    __tablename__ = "subscriptions"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, index=True, nullable=False)
    status = Column(String, nullable=False) # active, past_due, canceled

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="SaaS Payment Webhook Service")

# Segredo do Webhook fornecido pelo Gateway de Pagamento
WEBHOOK_SECRET = "whsec_test_secret_key_12345"

def verify_gateway_signature(payload: bytes, signature_header: Optional[str]) -> bool:
    """
    Valida a assinatura criptográfica enviada pelo gateway para garantir autenticidade.
    """
    if not signature_header:
        return False
    
    # Exemplo simplificado de validação HMAC-SHA256
    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_signature, signature_header)

@app.post("/api/v1/webhooks/payment", status_code=status.HTTP_200_OK)
async def payment_webhook(request: Request, db: Session = Depends(get_db)):
    # 1. Capturar o corpo bruto para validação de assinatura
    payload = await request.body()
    signature = request.headers.get("X-Gateway-Signature")
    
    # 2. Validar autenticidade da requisição
    if not verify_gateway_signature(payload, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Assinatura de webhook inválida."
        )
    
    try:
        event = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload JSON inválido."
        )
    
    event_type = event.get("type")
    data = event.get("data", {}).get("object", {})
    
    gateway_invoice_id = data.get("id")
    tenant_id = data.get("metadata", {}).get("tenant_id")
    
    if not gateway_invoice_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID da fatura ausente no payload."
        )

    # 3. Buscar a fatura na base de dados compartilhada filtrando pelo tenant_id e ID do gateway
    query = db.query(InvoiceModel).filter(InvoiceModel.gateway_invoice_id == gateway_invoice_id)
    if tenant_id:
        query = query.filter(InvoiceModel.tenant_id == int(tenant_id))
        
    invoice = query.first()
    
    if not invoice:
        # Fatura não encontrada na base da aplicação
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Fatura {gateway_invoice_id} não encontrada para o tenant especificado."
        )

    # 4. Interpretar o evento e atualizar o estado da fatura e da assinatura correspondente
    if event_type == "invoice.payment_succeeded":
        invoice.status = "paid"
        invoice.updated_at = datetime.utcnow()
        
        # Atualiza também o status da assinatura ativa do tenant para 'active'
        subscription = db.query(SubscriptionModel).filter(SubscriptionModel.tenant_id == invoice.tenant_id).first()
        if subscription:
            subscription.status = "active"
            
    elif event_type == "invoice.payment_failed":
        invoice.status = "failed"
        invoice.updated_at = datetime.utcnow()
        
        # Opcional: Atualizar plano/assinatura para past_due
        subscription = db.query(SubscriptionModel).filter(SubscriptionModel.tenant_id == invoice.tenant_id).first()
        if subscription:
            subscription.status = "past_due"
            
    elif event_type == "invoice.canceled":
        invoice.status = "canceled"
        invoice.updated_at = datetime.utcnow()

    # 5. Persistir as alterações de forma transacional
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao atualizar o estado da fatura no banco de dados."
        )

    return {"status": "success", "invoice_id": invoice.id, "state": invoice.status}