"""
Rota: POST /api/v1/integration-keys
Gera uma nova chave de integração para a empresa do usuário autenticado.
"""
import hashlib
import hmac
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger(__name__)

# Segredo do servidor (pepper). Deve vir de um cofre de segredos / variável de ambiente.
KEY_PEPPER = os.environ["INTEGRATION_KEY_PEPPER"].encode()
KEY_PREFIX_TAG = "sk_live_"


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class Company(Base):
    __tablename__ = "companies"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    max_integration_keys: Mapped[int] = mapped_column(default=5)  # limite do plano
    subscription_active: Mapped[bool] = mapped_column(default=True)


class IntegrationKey(Base):
    __tablename__ = "integration_keys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("companies.id"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(100))
    key_prefix: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(64))  # HMAC-SHA256 em hex
    created_by: Mapped[uuid.UUID] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# --------------------------------------------------------------------------- #
# Dependências (substitua pelas implementações reais da aplicação)
# --------------------------------------------------------------------------- #
class CurrentUser(BaseModel):
    id: uuid.UUID
    company_id: uuid.UUID
    role: str  # ex.: "admin", "member"


def get_db() -> Session:  # pragma: no cover
    raise NotImplementedError("Injete a sessão do SQLAlchemy")


def get_current_user() -> CurrentUser:  # pragma: no cover
    raise NotImplementedError("Injete o usuário autenticado (JWT/sessão)")


def require_company_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente.")
    return user


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class IntegrationKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    expires_in_days: int | None = Field(default=None, ge=1, le=730)


class IntegrationKeyCreated(BaseModel):
    id: uuid.UUID
    name: str
    key: str  # exibida UMA única vez
    key_prefix: str
    created_at: datetime
    expires_at: datetime | None


# --------------------------------------------------------------------------- #
# Utilitários de chave
# --------------------------------------------------------------------------- #
def hash_key(raw_key: str) -> str:
    return hmac.new(KEY_PEPPER, raw_key.encode(), hashlib.sha256).hexdigest()


def generate_key() -> tuple[str, str, str]:
    """Retorna (chave_completa, prefixo_público, hash)."""
    public_id = secrets.token_hex(4)          # 8 chars, identifica a chave
    secret = secrets.token_urlsafe(32)        # ~256 bits de entropia
    raw = f"{KEY_PREFIX_TAG}{public_id}_{secret}"
    return raw, f"{KEY_PREFIX_TAG}{public_id}", hash_key(raw)


def verify_key(db: Session, raw_key: str) -> IntegrationKey | None:
    """Uso na autenticação das chamadas de integração (comparação em tempo constante)."""
    try:
        prefix = raw_key.rsplit("_", 1)[0]
    except ValueError:
        return None
    record = db.scalar(select(IntegrationKey).where(IntegrationKey.key_prefix == prefix))
    if record is None or record.revoked_at is not None:
        return None
    if record.expires_at and record.expires_at <= datetime.now(timezone.utc):
        return None
    if not hmac.compare_digest(record.key_hash, hash_key(raw_key)):
        return None
    return record


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/api/v1/integration-keys", tags=["integration-keys"])


@router.post(
    "",
    response_model=IntegrationKeyCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_integration_key(
    payload: IntegrationKeyCreate,
    response: Response,
    user: CurrentUser = Depends(require_company_admin),
    db: Session = Depends(get_db),
) -> IntegrationKeyCreated:
    # O tenant é SEMPRE derivado do usuário autenticado.
    # Lock na linha da empresa: serializa criações concorrentes e protege o limite do plano.
    company = db.scalar(
        select(Company).where(Company.id == user.company_id).with_for_update()
    )
    if company is None or not company.subscription_active:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")

    active_keys = db.scalar(
        select(func.count())
        .select_from(IntegrationKey)
        .where(
            IntegrationKey.company_id == company.id,
            IntegrationKey.revoked_at.is_(None),
        )
    )
    if active_keys >= company.max_integration_keys:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Limite de chaves de integração do plano atingido.",
        )

    raw_key, prefix, key_hash = generate_key()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)
        if payload.expires_in_days
        else None
    )

    record = IntegrationKey(
        company_id=company.id,
        name=payload.name.strip(),
        key_prefix=prefix,
        key_hash=key_hash,
        created_by=user.id,
        expires_at=expires_at,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # Auditoria: nunca registrar a chave em texto puro.
    logger.info(
        "integration_key_created company=%s user=%s key_id=%s prefix=%s",
        company.id, user.id, record.id, prefix,
    )

    # Impede cache da resposta que contém o segredo.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return IntegrationKeyCreated(
        id=record.id,
        name=record.name,
        key=raw_key,
        key_prefix=prefix,
        created_at=record.created_at,
        expires_at=record.expires_at,
    )