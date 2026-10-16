from fastapi import FastAPI, Header, HTTPException, Request
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer
import hashlib
import hmac
import json
import os


DATABASE_URL= os.environ["DATABASE_URL"]
GATEWAY_WEBHOOK_SECRET= os.environ["GATEWAY_WEBHOOK_SECRET"]

engine= create_engine(DATABASE_URL, pool_pre_ping=True)
app= FastAPI()


class Base(DeclarativeBase):
    pass


class Invoice(Base):
    __tablename__= "invoices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    gateway_invoice_id: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(30), nullable=False)


def verify_signature(payload: bytes, signature: str)-> bool:
    expected= hmac.new(
        GATEWAY_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


@app.post("/api/webhooks/payment-gateway")
async def payment_gateway_webhook(
    request: Request,
    x_gateway_signature: str = Header(...),
):
    payload= await request.body()

    if not verify_signature(payload, x_gateway_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        message= json.loads(payload)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    event_type= message.get("event")
    data= message.get("data", {})

    gateway_invoice_id= data.get("invoice_id")
    tenant_id= data.get("tenant_id")
    new_status= data.get("status")

    if not all([event_type, gateway_invoice_id, tenant_id, new_status]):
        raise HTTPException(status_code=400, detail="Invalid webhook payload")

    allowed_statuses= {
        "pending",
        "paid",
        "failed",
        "cancelled",
        "refunded",
    }

    if new_statusnot in allowed_statuses:
        raise HTTPException(status_code=400, detail="Unsupported invoice status")

    with Session(engine) as session:
        invoice= session.scalar(
            select(Invoice).where(
                Invoice.gateway_invoice_id== gateway_invoice_id,
                Invoice.tenant_id== tenant_id,
            )
        )

        if invoice is None:
            raise HTTPException(status_code=404, detail="Invoice not found")

        invoice.status= new_status
        session.commit()

    return {"received": True}