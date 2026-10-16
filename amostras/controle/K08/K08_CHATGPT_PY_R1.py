from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

# Imports ilustrativos da camada de persistência da aplicação.
# A sessão deve ser criada pelo mecanismo de DI da aplicação.
from database import get_session
from models import Invoice, WebhookEvent


app = FastAPI()


class InvoiceStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    CANCELED = "canceled"


class PaymentWebhook(BaseModel):
    """
    Modelo mínimo esperado do gateway.

    Campos desconhecidos são ignorados para evitar que o restante do
    payload seja tratado como dado de negócio.
    """
    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)
    invoice_id: str = Field(min_length=1, max_length=100)
    status: str = Field(min_length=1, max_length=50)


WEBHOOK_SECRET = os.environ["PAYMENT_WEBHOOK_SECRET"]

# Transições permitidas. A lista deve refletir as regras reais do negócio.
ALLOWED_TRANSITIONS: dict[InvoiceStatus, set[InvoiceStatus]] = {
    InvoiceStatus.PENDING: {
        InvoiceStatus.PAID,
        InvoiceStatus.FAILED,
        InvoiceStatus.CANCELED,
    },
    InvoiceStatus.FAILED: {
        InvoiceStatus.PAID,
    },
    InvoiceStatus.PAID: set(),
    InvoiceStatus.CANCELED: set(),
}


def verify_signature(payload: bytes, received_signature: str) -> bool:
    """
    Valida a assinatura sobre os bytes EXATOS recebidos.

    Nunca desserializar/reserializar o JSON antes dessa verificação.
    """
    if not received_signature:
        return False

    expected = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    # Comparação em tempo constante.
    return hmac.compare_digest(expected, received_signature)


def normalize_gateway_status(value: str) -> InvoiceStatus:
    mapping = {
        "paid": InvoiceStatus.PAID,
        "payment_succeeded": InvoiceStatus.PAID,
        "failed": InvoiceStatus.FAILED,
        "payment_failed": InvoiceStatus.FAILED,
        "canceled": InvoiceStatus.CANCELED,
        "cancelled": InvoiceStatus.CANCELED,
        "pending": InvoiceStatus.PENDING,
    }

    try:
        return mapping[value.lower()]
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported payment status",
        )


@app.post(
    "/api/v1/webhooks/payment",
    status_code=status.HTTP_202_ACCEPTED,
)
async def payment_webhook(
    request: Request,
    x_gateway_signature: str | None = Header(default=None),
):
    """
    Endpoint público para notificações do gateway.

    O endpoint não recebe tenant_id.
    O tenant é descoberto exclusivamente através da fatura.
    """

    # 1. Ler o corpo bruto para validar a assinatura.
    raw_body = await request.body()

    # 2. Evitar processamento de payloads excessivamente grandes.
    # Idealmente, também configurar esse limite no reverse proxy/API gateway.
    max_body_size = 64 * 1024

    if len(raw_body) > max_body_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload too large",
        )

    # 3. Autenticar a origem antes de processar os dados.
    if not verify_signature(raw_body, x_gateway_signature or ""):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    # 4. Fazer parsing somente depois da autenticação.
    try:
        decoded = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON",
        )

    if not isinstance(decoded, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid payload",
        )

    try:
        webhook = PaymentWebhook.model_validate(decoded)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid webhook schema",
        )

    # get_session representa a dependência que fornece uma sessão transacional.
    async with get_session() as session:
        # 5. Idempotência:
        # event_id deve possuir uma UNIQUE CONSTRAINT no banco.
        existing_event = await session.scalar(
            select(WebhookEvent).where(
                WebhookEvent.event_id == webhook.event_id
            )
        )

        if existing_event is not None:
            # O gateway pode reenviar o mesmo evento várias vezes.
            return {"received": True}

        # 6. Procurar a fatura pelo identificador externo.
        #
        # IMPORTANTE:
        # Não fazemos:
        #   Invoice.tenant_id == payload["tenant_id"]
        #
        # O tenant é determinado pela própria fatura.
        invoice = await session.scalar(
            select(Invoice)
            .where(
                Invoice.gateway_invoice_id == webhook.invoice_id
            )
            .with_for_update()
        )

        if invoice is None:
            # Não revelar detalhes internos da base.
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invoice not found",
            )

        new_status = normalize_gateway_status(webhook.status)

        current_status = InvoiceStatus(invoice.status)

        # 7. Aplicar somente transições válidas.
        if new_status != current_status:
            allowed = ALLOWED_TRANSITIONS.get(current_status, set())

            if new_status not in allowed:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Invalid invoice state transition",
                )

            invoice.status = new_status

            if new_status == InvoiceStatus.PAID:
                invoice.paid_at = datetime.now(timezone.utc)

        # 8. Registrar o evento processado na MESMA transação.
        event = WebhookEvent(
            event_id=webhook.event_id,
            event_type=webhook.event_type,
            invoice_id=invoice.id,
            received_at=datetime.now(timezone.utc),
        )

        session.add(event)

        try:
            await session.commit()
        except IntegrityError:
            # Duas requisições simultâneas podem ter recebido o mesmo
            # event_id. A UNIQUE CONSTRAINT torna a operação idempotente.
            await session.rollback()
            return {"received": True}

    return {"received": True}
