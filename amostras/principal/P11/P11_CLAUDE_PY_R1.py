"""
Rota: POST /api/v1/integration-keys
Gera uma chave de integração para a empresa (tenant) do usuário autenticado.
"""
import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import JSON, DateTime, ForeignKey, String, Uuid, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
# Segredo ("pepper") mantido fora do banco (variável de ambiente / secret manager).
KEY_PEPPER = os.environ["INTEGRATION_KEY_PEPPER"].encode()

KEY_ENV_PREFIX = "sk_live"
ALLOWED_SCOPES = {"read:customers", "write:customers", "read:invoices", "write:invoices"}
MAX_KEYS_BY_PLAN = {"basic": 2, "pro": 10, "enterprise": 50}
MAX_TTL_DAYS = 365


# ---------------------------------------------------------------------------
# Modelos (simplificados; Company e User já existem na aplicação)
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class Company(Base):
    __tablename__ = "companies"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    plan: Mapped[str] = mapped_column(String(32))
    subscription_status: Mapped[str] = mapped_column(String(32))  # active, past_due, canceled...


class IntegrationKey(Base):
    __tablename__ = "integration_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("companies.id"), index=True)
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    name: Mapped[str] = mapped_column(String(100))
    key_prefix: Mapped[str] = mapped_column(String(16), unique=True)   # identificador público
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)     # HMAC-SHA256 (nunca o valor puro)
    scopes: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ---------------------------------------------------------------------------
# Dependências fornecidas pela camada de autenticação da aplicação
# ---------------------------------------------------------------------------
class CurrentUser(BaseModel):
    id: uuid.UUID
    company_id: uuid.UUID   # vem do token/sessão validado, NUNCA do corpo da requisição
    role: str               # ex.: "owner", "admin", "member"


def get_db() -> Session: ...                      # sessão por requisição
def get_current_user() -> CurrentUser: ...        # valida JWT/sessão


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class IntegrationKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(min_length=1)
    expires_in_days: Optional[int] = Field(default=90, ge=1, le=MAX_TTL_DAYS)


class IntegrationKeyCreated(BaseModel):
    id: uuid.UUID
    name: str
    key: str                  # exibida UMA única vez
    key_prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: Optional[datetime]


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------
def hash_key(raw_key: str) -> str:
    return hmac.new(KEY_PEPPER, raw_key.encode(), hashlib.sha256).hexdigest()


def generate_raw_key() -> tuple[str, str]:
    """Retorna (chave_completa, prefixo). Formato: sk_live_<prefixo>_<segredo>"""
    prefix = secrets.token_hex(4)            # 8 chars, identifica a chave em logs/UI
    secret = secrets.token_urlsafe(32)       # ~256 bits de entropia (CSPRNG)
    return f"{KEY_ENV_PREFIX}_{prefix}_{secret}", prefix


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1", tags=["integration-keys"])


@router.post(
    "/integration-keys",
    response_model=IntegrationKeyCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_integration_key(
    payload: IntegrationKeyCreate,
    response: Response,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    # 1. Autorização: apenas perfis administrativos criam credenciais.
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente.")

    # 2. Validação de escopos (lista fechada).
    invalid = set(payload.scopes) - ALLOWED_SCOPES
    if invalid:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Escopos inválidos: {sorted(invalid)}",
        )

    # 3. Tenant vem exclusivamente do usuário autenticado.
    #    Lock na linha da empresa evita que requisições concorrentes
    #    ultrapassem o limite do plano.
    company = db.execute(
        select(Company).where(Company.id == user.company_id).with_for_update()
    ).scalar_one_or_none()
    if company is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Empresa não encontrada.")

    # 4. Assinatura ativa e limite de chaves do plano.
    if company.subscription_status != "active":
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")

    now = datetime.now(timezone.utc)
    active_keys = db.execute(
        select(func.count(IntegrationKey.id)).where(
            IntegrationKey.company_id == company.id,
            IntegrationKey.revoked_at.is_(None),
            (IntegrationKey.expires_at.is_(None)) | (IntegrationKey.expires_at > now),
        )
    ).scalar_one()
    if active_keys >= MAX_KEYS_BY_PLAN.get(company.plan, 0):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Limite de chaves do plano atingido. Revogue uma chave ou faça upgrade.",
        )

    # 5. Gera e persiste (apenas o hash). Repete em caso de colisão de prefixo.
    for _ in range(3):
        raw_key, prefix = generate_raw_key()
        record = IntegrationKey(
            company_id=company.id,
            created_by_user_id=user.id,
            name=payload.name.strip(),
            key_prefix=prefix,
            key_hash=hash_key(raw_key),
            scopes=sorted(set(payload.scopes)),
            expires_at=now + timedelta(days=payload.expires_in_days)
            if payload.expires_in_days
            else None,
        )
        db.add(record)
        try:
            db.commit()
            break
        except IntegrityError:
            db.rollback()
            # reabre o lock após rollback
            db.execute(select(Company).where(Company.id == user.company_id).with_for_update())
    else:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Falha ao gerar a chave.")

    db.refresh(record)
    # (Aqui: registrar evento de auditoria — quem criou, qual empresa, id/prefixo da chave,
    #  NUNCA o valor da chave.)

    # 6. A resposta contém o segredo: impedir cache.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return IntegrationKeyCreated(
        id=record.id,
        name=record.name,
        key=raw_key,
        key_prefix=record.key_prefix,
        scopes=record.scopes,
        created_at=record.created_at,
        expires_at=record.expires_at,
    )