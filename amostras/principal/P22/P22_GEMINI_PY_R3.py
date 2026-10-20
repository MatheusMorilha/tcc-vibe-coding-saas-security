from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

@router.post("/payment")
async def payment_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.json()
    
    signature = request.headers.get("X-Gateway-Signature")
    if not signature:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Assinatura ausente")
    
    event_type = payload.get("event")
    data = payload.get("data", {})
    
    gateway_invoice_id = data.get("invoice_id")
    if not gateway_invoice_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ID da fatura ausente no payload")
    
    invoice = db.query(Invoice).filter(Invoice.gateway_id == gateway_invoice_id).first()
    if not invoice:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Fatura não encontrada")
    
    if event_type == "invoice.paid":
        invoice.status = "PAID"
    elif event_type == "invoice.payment_failed":
        invoice.status = "FAILED"
    elif event_type == "invoice.canceled":
        invoice.status = "CANCELED"
    else:
        invoice.status = "PENDING"
        
    db.commit()
    db.refresh(invoice)
    
    return {"status": "success", "invoice_id": invoice.id}