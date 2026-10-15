import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, func, select
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, ARRAY
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

# Segredo (pepper) mantido fora do banco: variável de ambiente / secret manager.
KEY_HASH_PEPPER = os.environ["INTEGRATION_KEY_PEPPER"].encode()

KEY_PREFIX_TAG = "ik"          # identifica o tipo de credencial (útil em secret scanning)
KEY_PREFIX_LENGTH = 8          # parte pública usada para localizar/listar a chave
ALLOWED_SCOPES = {"read", "write", "webhooks"}
MAX_EXPIRATION_DAYS = 365


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class Company(Base):
    __tablename__ = "companies"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    plan_active: Mapped[bool] = mapped_column(Boolean, default=True)
    plan_max_integration_keys: Mapped[int] = mapped_column(Integer, default=5)


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    company_id: Mapped[UUID] = mapped_column(ForeignKey("companies.id"), index=True)
    is_company_admin: Mapped[bool] = mapped_column(Boolean, default=False)


class IntegrationKey(Base):
    __tablename__ = "integration_keys"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    company_id: Mapped[UUID] = mapped_column(ForeignKey("companies.id"), index=True)
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(100))
    key_prefix: Mapped[str] = mapped_column(String(32), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)  # hex SHA-256
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ---------------------------------------------------------------------------
# Dependências (a serem fornecidas pela aplicação)
# ---------------------------------------------------------------------------

def get_db() -> Session:
    """Retorna uma sessão do SQLAlchemy (implementação da aplicação)."""
    raise NotImplementedError


def get_current_user() -> User:
    """Retorna o usuário autenticado a partir do token (implementação da aplicação)."""
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class IntegrationKeyCreate(BaseModel):
    name: str = Field(min_length=3, max_length=100)
    scopes: list[str] = Field(default_factory=lambda: ["read"], min_length=1)
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=MAX_EXPIRATION_DAYS)


class IntegrationKeyCreated(BaseModel):
    id: UUID
    name: str
    key: str  # exibida somente nesta resposta
    key_prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: Optional[datetime]


# ---------------------------------------------------------------------------
# Funções auxiliares
# ---------------------------------------------------------------------------

def hash_key(raw_key: str) -> str:
    """HMAC-SHA256 com pepper. Chaves têm alta entropia, então não precisam de KDF lento."""
    return hmac.new(KEY_HASH_PEPPER, raw_key.encode(), hashlib.sha256).hexdigest()


def generate_raw_key() -> tuple[str, str]:
    """Retorna (chave_completa, prefixo_publico)."""
    public_part = secrets.token_hex(KEY_PREFIX_LENGTH // 2)
    secret_part = secrets.token_urlsafe(32)
    prefix = f"{KEY_PREFIX_TAG}_{public_part}"
    return f"{prefix}_{secret_part}", prefix


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/integration-keys", tags=["integration-keys"])


@router.post(
    "",
    response_model=IntegrationKeyCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Gera uma nova chave de integração para a empresa do usuário autenticado",
)
def create_integration_key(
    payload: IntegrationKeyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # 1. Autorização: apenas administradores da empresa.
    if not current_user.is_company_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente.")

    # 2. Validação dos escopos solicitados.
    invalid = set(payload.scopes) - ALLOWED_SCOPES
    if invalid:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Escopos inválidos: {sorted(invalid)}",
        )

    # 3. O tenant vem SEMPRE do usuário autenticado.
    #    Bloqueia a linha da empresa para serializar criações concorrentes.
    company = db.execute(
        select(Company).where(Company.id == current_user.company_id).with_for_update()
    ).scalar_one_or_none()

    if company is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Empresa não encontrada.")

    # 4. Plano de assinatura ativo.
    if not company.plan_active:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa. Regularize seu plano."
        )

    # 5. Limite de chaves do plano (somente chaves vigentes, filtradas pelo tenant).
    now = datetime.now(timezone.utc)
    active_count = db.execute(
        select(func.count(IntegrationKey.id)).where(
            IntegrationKey.company_id == company.id,
            IntegrationKey.revoked_at.is_(None),
            (IntegrationKey.expires_at.is_(None)) | (IntegrationKey.expires_at > now),
        )
    ).scalar_one()

    if active_count >= company.plan_max_integration_keys:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Limite de chaves de integração do plano atingido.",
        )

    # 6. Geração e persistência (apenas o hash é armazenado).
    raw_key, prefix = generate_raw_key()
    expires_at = (
        now + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None
    )

    record = IntegrationKey(
        company_id=company.id,
        created_by=current_user.id,
        name=payload.name.strip(),
        key_prefix=prefix,
        key_hash=hash_key(raw_key),
        scopes=sorted(set(payload.scopes)),
        expires_at=expires_at,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # 7. Retorna a chave em texto puro uma única vez.
    return IntegrationKeyCreated(
        id=record.id,
        name=record.name,
        key=raw_key,
        key_prefix=record.key_prefix,
        scopes=record.scopes,
        created_at=record.created_at,
        expires_at=record.expires_at,
    )