# integration_keys.py
import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, JSON, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

# Supostamente já existentes no projeto:
from app.db import Base, get_db                      # sessão e declarative base
from app.auth import get_current_user, AuthUser      # AuthUser: id, tenant_id, role
from app.models import Tenant, AuditLog              # Tenant.plan.max_integration_keys

router = APIRouter(prefix="/api/v1/integration-keys", tags=["integration-keys"])

KEY_PEPPER = os.environ["INTEGRATION_KEY_PEPPER"].encode()  # falha cedo se ausente
KEY_ID_PREFIX = "ik"
ALLOWED_SCOPES = {"read:customers", "write:customers", "read:invoices", "write:invoices"}


# ---------- Modelo ----------
class IntegrationKey(Base):
    __tablename__ = "integration_keys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    prefix: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ---------- Schemas ----------
class CreateKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(min_length=1)
    expires_in_days: Optional[int] = Field(default=90, ge=1, le=365)


class CreateKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    scopes: list[str]
    created_at: datetime
    expires_at: Optional[datetime]
    api_key: str  # exibida somente nesta resposta


# ---------- Utilitários ----------
def hash_key(raw_key: str) -> str:
    return hmac.new(KEY_PEPPER, raw_key.encode(), hashlib.sha256).hexdigest()


def generate_key() -> tuple[str, str, str]:
    """Retorna (chave_completa, prefixo_publico, hash)."""
    prefix = f"{KEY_ID_PREFIX}_{secrets.token_hex(6)}"
    secret = secrets.token_urlsafe(32)
    raw_key = f"{prefix}.{secret}"
    return raw_key, prefix, hash_key(raw_key)


# ---------- Rota ----------
@router.post("", response_model=CreateKeyResponse, status_code=status.HTTP_201_CREATED)
def create_integration_key(
    payload: CreateKeyRequest,
    response: Response,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(get_current_user),
):
    # 1. Autorização
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Apenas administradores podem criar chaves.")

    # 2. Validação de escopos
    invalid = set(payload.scopes) - ALLOWED_SCOPES
    if invalid:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"Escopos inválidos: {sorted(invalid)}")

    # 3. Tenant vem SEMPRE do usuário autenticado
    tenant_id = user.tenant_id

    # 4. Transação: lock na linha da empresa para serializar a checagem do limite
    with db.begin_nested() if db.in_transaction() else db.begin():
        tenant = db.execute(
            select(Tenant).where(Tenant.id == tenant_id).with_for_update()
        ).scalar_one()

        if tenant.subscription_status != "active":
            raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")

        active_count = db.execute(
            select(func.count(IntegrationKey.id)).where(
                IntegrationKey.tenant_id == tenant_id,
                IntegrationKey.revoked_at.is_(None),
            )
        ).scalar_one()

        if active_count >= tenant.plan.max_integration_keys:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "Limite de chaves do plano atingido.")

        raw_key, prefix, key_hash = generate_key()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None

        key = IntegrationKey(
            tenant_id=tenant_id,
            name=payload.name.strip(),
            prefix=prefix,
            key_hash=key_hash,
            scopes=sorted(set(payload.scopes)),
            created_by=user.id,
            expires_at=expires_at,
        )
        db.add(key)
        db.flush()  # obtém id/created_at

        # Auditoria (sem a chave!)
        db.add(AuditLog(
            tenant_id=tenant_id,
            actor_id=user.id,
            action="integration_key.created",
            target_id=str(key.id),
            metadata_={"name": key.name, "scopes": key.scopes, "prefix": prefix},
        ))

    db.commit()

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return CreateKeyResponse(
        id=key.id,
        name=key.name,
        scopes=key.scopes,
        created_at=key.created_at,
        expires_at=key.expires_at,
        api_key=raw_key,
    )