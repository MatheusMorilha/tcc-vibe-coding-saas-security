import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# --- MODELO DE BANCO DE DADOS (SQLAlchemy) ---
Base = declarative_base()


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(
        Integer, nullable=False, index=True
    )  # Isolamento multilocatário
    name = Column(
        String(100), nullable=False
    )  # Identificador amigável (ex: "Integração CRM")
    key_hash = Column(
        String(64), nullable=False, unique=True, index=True
    )  # Hash SHA-256 da chave
    prefix = Column(
        String(12), nullable=False
    )  # Primeiros caracteres visíveis para identificação
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    revoked_at = Column(DateTime(timezone=True), nullable=True)


# --- SCHEMAS DE ENTRADA E SAÍDA (Pydantic) ---
class CreateAPIKeyRequest(BaseModel):
    name: str


class CreateAPIKeyResponse(BaseModel):
    id: int
    name: str
    api_key: str  # Exibida APENAS nesta resposta (raw token)
    prefix: str
    created_at: datetime

    class Config:
        from_attributes = True


# --- MOCK DE INJEÇÃO DE DEPENDÊNCIA DE AUTENTICAÇÃO ---
class UserSession(BaseModel):
    user_id: int
    tenant_id: int
    role: str


def get_current_user() -> UserSession:
    """Extrai o usuário do Token JWT/Sessão.

    Garante o contexto do Tenant atual.
    """
    # Em produção, extraia do cabeçalho de autorização (Bearer token)
    return UserSession(user_id=42, tenant_id=1001, role="admin")


def get_db():
    """Gerenciador de sessão do SQLAlchemy."""
    db = sessionmaker(bind=create_engine("sqlite:///./app.db"))()
    try:
        yield db
    finally:
        db.close()


# --- ROTA DA API ---
router = APIRouter(prefix="/api/v1/integration-keys", tags=["Integration Keys"])


@router.post(
    "",
    response_model=CreateAPIKeyResponse,
    status_code=status.HTTP_21_CREATED,
    summary="Gera uma nova chave de integração para a empresa",)
def generate_integration_key(
    payload: CreateAPIKeyRequest,
    db: Session = Depends(get_db),
    current_user: UserSession = Depends(get_current_user),):
    # 1. Validação de Controle de Acesso (RBAC)
    if current_user.role not in ["admin", "owner"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas administradores podem gerar chaves de integração.",
        )

    # 2. Geração da chave criptográfica
    raw_key = f"sk_live_{secrets.token_urlsafe(32)}"
    key_prefix = raw_key[:12]

    # 3. Hash da chave para armazenamento seguro (SHA-256)
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    # 4. Criação do registro no banco vinculado estritamente ao tenant_id do usuário
    new_api_key = APIKey(
        tenant_id=current_user.tenant_id,
        name=payload.name,
        key_hash=key_hash,
        prefix=key_prefix,
    )

    db.add(new_api_key)
    db.commit()
    db.refresh(new_api_key)

    # 5. Retorno com a chave completa em texto claro (única oportunidade de visualização)
    return CreateAPIKeyResponse(
        id=new_api_key.id,
        name=new_api_key.name,
        api_key=raw_key,
        prefix=new_api_key.prefix,
        created_at=new_api_key.created_at,
    )