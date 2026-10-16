"""
Webhook do gateway de pagamento - plataforma SaaS multilocatária.

Dependências: fastapi, sqlalchemy>=2.0, pydantic>=2
Variáveis de ambiente:
    PAYMENT_WEBHOOK_SECRETS  segredos HMAC separados por vírgula (o primeiro é o
                             atual; os demais permitem rotação sem downtime)
    DATABASE_URL             string de conexão (usuário de BD com privilégio mínimo)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import (
    BigInteger, DateTime, ForeignKey, String, UniqueConstraint,
    create_engine, select,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

logger = logging.getLogger("billing.webhook")

# --------------------------------------------------------------------------- #
# Configuração (A05: sem segredos no código; falha rápida se ausentes)
# --------------------------------------------------------------------------- #
_RAW_SECRETS = os.environ.get("PAYMENT_WEBHOOK_SECRETS", "")
WEBHOOK_SECRETS: list[bytes] = [s.strip().encode() for s in _RAW_SECRETS.split(",") if s.strip()]
if not WEBHOOK_SECRETS:
    raise RuntimeError("PAYMENT_WEBHOOK_SECRETS não configurado")

MAX_BODY_BYTES = 64 * 1024          # A04/A05: limita o tamanho do corpo
TIMESTAMP_TOLERANCE_S = 300         # A08: janela anti-replay (5 min)
PROVIDER = "acme_gateway"

engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class Invoice(Base):
    __tablename__ = "invoices"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    gateway_invoice_id: Mapped[str] = mapped_column(String(100), unique=True)
    amount_cents: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class WebhookEvent(Base):
    """Registro de idempotência + trilha de auditoria (A09)."""
    __tablename__ = "webhook_events"
    __table_args__ = (UniqueConstraint("provider", "event_id", name="uq_provider_event"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(50))
    event_id: Mapped[str] = mapped_column(String(100))
    event_type: Mapped[str] = mapped_column(String(50))
    tenant_id: Mapped[int | None] = mapped_column(index=True)
    invoice_id: Mapped[int | None] = mapped_column(index=True)
    outcome: Mapped[str] = mapped_column(String(30))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------- #
# Schema de entrada (A03/A04: validação estrita, allow-list de tipos de evento)
# --------------------------------------------------------------------------- #
class InvoiceData(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    invoice_id: str = Field(pattern=r"^[A-Za-z0-9_\-]{1,100}$")
    amount_cents: int = Field(ge=0, le=10**12)
    currency: str = Field(pattern=r"^[A-Z]{3}$")


class WebhookPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    event_id: str = Field(pattern=r"^[A-Za-z0-9_\-]{1,100}$")
    type: Literal[
        "invoice.paid", "invoice.payment_failed", "invoice.voided", "invoice.refunded"
    ]
    data: InvoiceData


EVENT_TO_STATUS = {
    "invoice.paid": "paid",
    "invoice.payment_failed": "failed",
    "invoice.voided": "void",
    "invoice.refunded": "refunded",
}

# Máquina de estados: impede regressões e eventos fora de ordem (A04/A08)
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "pending": {"paid", "failed", "void"},
    "failed": {"paid", "void"},
    "paid": {"refunded"},
    "void": set(),
    "refunded": set(),
}


# --------------------------------------------------------------------------- #
# Autenticidade e integridade (A02/A07/A08)
# --------------------------------------------------------------------------- #
def _verify_signature(raw_body: bytes, header: str | None) -> bool:
    """Header esperado: 't=<unix_ts>,v1=<hex_hmac_sha256>' sobre f'{t}.{body}'."""
    if not header or len(header) > 512:
        return False
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts = int(parts["t"])
        received_sig = parts["v1"]
    except (ValueError, KeyError):
        return False

    if abs(time.time() - ts) > TIMESTAMP_TOLERANCE_S:
        return False

    signed = f"{ts}.".encode() + raw_body
    ok = False
    for secret in WEBHOOK_SECRETS:  # sem early-return: tempo constante entre segredos
        expected = hmac.new(secret, signed, hashlib.sha256).hexdigest()
        ok |= hmac.compare_digest(expected, received_sig)
    return ok


async def _read_limited_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
        chunks.append(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------- #
# Regra de negócio (executada em thread; uma única transação)
# --------------------------------------------------------------------------- #
def _process_event(payload: WebhookPayload) -> str:
    now = datetime.now(timezone.utc)
    target_status = EVENT_TO_STATUS[payload.type]

    with SessionLocal() as db, db.begin():
        # Consulta parametrizada via ORM (A03). Lock de linha evita corrida
        # entre entregas concorrentes do mesmo evento/fatura.
        invoice = db.execute(
            select(Invoice)
            .where(Invoice.gateway_invoice_id == payload.data.invoice_id)
            .with_for_update()
        ).scalar_one_or_none()

        def record(outcome: str) -> str:
            db.add(WebhookEvent(
                provider=PROVIDER, event_id=payload.event_id, event_type=payload.type,
                tenant_id=invoice.tenant_id if invoice else None,
                invoice_id=invoice.id if invoice else None,
                outcome=outcome, received_at=now,
            ))
            return outcome

        # Idempotência: a constraint única é a garantia final (A04/A08)
        try:
            with db.begin_nested():
                if invoice is None:
                    outcome = record("unknown_invoice")
                    db.flush()
                    logger.warning("webhook: fatura desconhecida event=%s", payload.event_id)
                    return outcome
                # O tenant vem SEMPRE do registro da fatura, nunca do payload (A01)
                if payload.data.currency != invoice.currency or \
                        payload.data.amount_cents != invoice.amount_cents:
                    outcome = record("amount_mismatch")
                    db.flush()
                    logger.error(
                        "webhook: divergência de valor/moeda event=%s tenant=%s invoice=%s",
                        payload.event_id, invoice.tenant_id, invoice.id,
                    )
                    return outcome

                if target_status == invoice.status:
                    outcome = record("noop")
                elif target_status not in ALLOWED_TRANSITIONS.get(invoice.status, set()):
                    outcome = record("transition_rejected")
                    logger.warning(
                        "webhook: transição inválida %s->%s tenant=%s invoice=%s",
                        invoice.status, target_status, invoice.tenant_id, invoice.id,
                    )
                else:
                    invoice.status = target_status
                    invoice.updated_at = now
                    if target_status == "paid":
                        invoice.paid_at = now
                    outcome = record("applied")
                    logger.info(
                        "webhook: fatura atualizada tenant=%s invoice=%s status=%s",
                        invoice.tenant_id, invoice.id, target_status,
                    )
                db.flush()
                return outcome
        except IntegrityError:
            return "duplicate"  # evento já processado: responde 200 sem reaplicar


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
router = APIRouter()


@router.post("/webhooks/payments", include_in_schema=False)
async def payment_webhook(
    request: Request,
    x_gateway_signature: str | None = Header(default=None),
) -> Response:
    # Rota pública por natureza: a autenticação é a assinatura, não sessão/JWT.
    # Rate limiting e allowlist de IPs do gateway devem ser aplicados no WAF/proxy.
    raw_body = await _read_limited_body(request)

    # 1) Autenticidade ANTES de qualquer parsing (A07/A08)
    if not _verify_signature(raw_body, x_gateway_signature):
        logger.warning("webhook: assinatura inválida")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    # 2) Parsing e validação estrita (A03)
    try:
        payload = WebhookPayload.model_validate(json.loads(raw_body))
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError):
        # Resposta genérica: não vaza detalhes do schema (A05)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid payload")

    # 3) Atualização transacional e idempotente
    try:
        await run_in_threadpool(_process_event, payload)
    except SQLAlchemyError:
        # Detalhes só no log do servidor (A05/A09); 503 faz o gateway reenviar
        logger.exception("webhook: falha de persistência event=%s", payload.event_id)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="Try again later")

    # 200 também para duplicados/ignorados, para o gateway não ficar reenviando
    return Response(status_code=status.HTTP_200_OK)