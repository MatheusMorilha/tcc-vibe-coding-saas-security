from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Invoice, WebhookEvent


router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Em produção, carregue isso de um secret manager/vault.
WEBHOOK_SECRET = os.environ["PAYMENT_WEBHOOK_SECRET"]

# Limite defensivo contra payloads excessivamente grandes.
MAX_BODY_SIZE = 1_000_000  # 1 MB


class InvoiceStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    REFUNDED = "refunded"
    CANCELED = "canceled"


class WebhookProcessingError(Exception):
    pass


def verify_signature(
    payload: bytes,
    signature: str | None,
) -> bool:
    """
    Valida a assinatura enviada pelo gateway.

    Esperamos:
        X-Webhook-Signature: sha256=<hex>

    O compare_digest evita comparações suscetíveis a timing attacks.
    """
    if not signature:
        return False

    prefix = "sha256="

    if not signature.startswith(prefix):
        return False

    received_signature = signature[len(prefix):]

    # Evita aceitar assinaturas com tamanho arbitrário.
    if len(received_signature) != 64:
        return False

    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        received_signature,
        expected_signature,
    )


def parse_gateway_event(payload: bytes) -> dict[str, Any]:
    """
    Interpreta o payload do gateway.

    O formato abaixo é propositalmente genérico.
    Adapte os campos ao gateway utilizado.
    """
    try:
        data = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebhookProcessingError("Invalid JSON") from exc

    if not isinstance(data, dict):
        raise WebhookProcessingError("Invalid webhook structure")

    event_id = data.get("id")
    event_type = data.get("type")
    invoice_external_id = data.get("invoice_id")

    if not isinstance(event_id, str) or not event_id:
        raise WebhookProcessingError("Missing event id")

    if not isinstance(event_type, str) or not event_type:
        raise WebhookProcessingError("Missing event type")

    if not isinstance(invoice_external_id, str) or not invoice_external_id:
        raise WebhookProcessingError("Missing invoice id")

    return {
        "id": event_id,
        "type": event_type,
        "invoice_id": invoice_external_id,
        "data": data.get("data", {}),
    }


def map_event_to_invoice_status(event_type: str) -> InvoiceStatus | None:
    """
    Faz o mapeamento explícito dos eventos suportados.

    Eventos desconhecidos não alteram a fatura.
    """
    mapping = {
        "invoice.paid": InvoiceStatus.PAID,
        "payment.succeeded": InvoiceStatus.PAID,
        "invoice.payment_failed": InvoiceStatus.FAILED,
        "payment.failed": InvoiceStatus.FAILED,
        "invoice.refunded": InvoiceStatus.REFUNDED,
        "invoice.canceled": InvoiceStatus.CANCELED,
    }

    return mapping.get(event_type)


def transition_is_valid(
    current: InvoiceStatus,
    new: InvoiceStatus,
) -> bool:
    """
    Impede algumas transições inconsistentes.

    A regra real deve refletir o domínio da aplicação.
    """
    allowed_transitions: dict[InvoiceStatus, set[InvoiceStatus]] = {
        InvoiceStatus.PENDING: {
            InvoiceStatus.PAID,
            InvoiceStatus.FAILED,
            InvoiceStatus.CANCELED,
        },
        InvoiceStatus.FAILED: {
            InvoiceStatus.PAID,
            InvoiceStatus.CANCELED,
        },
        InvoiceStatus.PAID: {
            InvoiceStatus.REFUNDED,
        },
        InvoiceStatus.REFUNDED: set(),
        InvoiceStatus.CANCELED: set(),
    }

    return (
        current == new
        or new in allowed_transitions.get(current, set())
    )


@router.post(
    "/payment",
    status_code=status.HTTP_200_OK,
)
async def payment_webhook(
    request: Request,
    x_webhook_signature: str | None = Header(
        default=None,
        alias="X-Webhook-Signature",
    ),
    db: Session = Depends(get_db),
):
    # ---------------------------------------------------------
    # 1. Ler o corpo bruto.
    #
    # A assinatura deve ser validada sobre os bytes originais,
    # antes de fazer parsing ou normalização do JSON.
    # ---------------------------------------------------------
    body = await request.body()

    if len(body) > MAX_BODY_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload too large",
        )

    # ---------------------------------------------------------
    # 2. Autenticar a origem do webhook.
    #
    # Não processe absolutamente nada antes dessa validação.
    # ---------------------------------------------------------
    if not verify_signature(body, x_webhook_signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    # ---------------------------------------------------------
    # 3. Interpretar o evento.
    # ---------------------------------------------------------
    try:
        event = parse_gateway_event(body)
    except WebhookProcessingError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid webhook payload",
        )

    event_id = event["id"]
    event_type = event["type"]
    external_invoice_id = event["invoice_id"]

    # ---------------------------------------------------------
    # 4. Idempotência.
    #
    # O gateway pode entregar o mesmo webhook várias vezes.
    #
    # A tabela WebhookEvent deve possuir UNIQUE(event_id).
    # ---------------------------------------------------------
    existing_event = db.execute(
        select(WebhookEvent).where(
            WebhookEvent.event_id == event_id
        )
    ).scalar_one_or_none()

    if existing_event is not None:
        # Não é necessário reprocessar.
        return {
            "status": "already_processed",
        }

    # ---------------------------------------------------------
    # 5. Eventos desconhecidos.
    #
    # É possível registrá-los sem alterar qualquer fatura.
    # ---------------------------------------------------------
    new_status = map_event_to_invoice_status(event_type)

    # ---------------------------------------------------------
    # 6. Localizar a fatura.
    #
    # IMPORTANTE:
    #
    # NÃO fazemos:
    #
    #     invoice.tenant_id = payload["tenant_id"]
    #
    # O tenant vem da própria relação persistida entre a fatura
    # e a empresa.
    # ---------------------------------------------------------
    invoice = db.execute(
        select(Invoice)
        .where(
            Invoice.external_gateway_invoice_id
            == external_invoice_id
        )
        .with_for_update()
    ).scalar_one_or_none()

    if invoice is None:
        # Não revelar detalhes internos do banco.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invoice not found",
        )

    # ---------------------------------------------------------
    # 7. Criar registro de auditoria/idempotência.
    # ---------------------------------------------------------
    webhook_event = WebhookEvent(
        id=uuid.uuid4(),
        event_id=event_id,
        event_type=event_type,
        tenant_id=invoice.tenant_id,
        invoice_id=invoice.id,
        received_at=datetime.now(timezone.utc),
    )

    db.add(webhook_event)

    # ---------------------------------------------------------
    # 8. Aplicar somente transições conhecidas.
    # ---------------------------------------------------------
    if new_status is not None:
        current_status = InvoiceStatus(invoice.status)

        if not transition_is_valid(
            current=current_status,
            new=new_status,
        ):
            # O evento foi autenticado, mas representa uma
            # transição incompatível com o estado atual.
            #
            # Registramos o evento, mas não alteramos a fatura.
            db.commit()

            return {
                "status": "ignored",
                "reason": "invalid_state_transition",
            }

        invoice.status = new_status.value
        invoice.updated_at = datetime.now(timezone.utc)

        if new_status == InvoiceStatus.PAID:
            invoice.paid_at = datetime.now(timezone.utc)

    # ---------------------------------------------------------
    # 9. Commit atômico.
    #
    # O registro do webhook e a alteração da fatura são
    # persistidos na mesma transação.
    # ---------------------------------------------------------
    try:
        db.commit()

    except IntegrityError:
        # Outro worker/processo pode ter processado o mesmo
        # event_id simultaneamente.
        db.rollback()

        existing_event = db.execute(
            select(WebhookEvent).where(
                WebhookEvent.event_id == event_id
            )
        ).scalar_one_or_none()

        if existing_event is not None:
            return {
                "status": "already_processed",
            }

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook processing failed",
        )

    return {
        "status": "processed",
    }
