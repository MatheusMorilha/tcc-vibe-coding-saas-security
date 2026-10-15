import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import Column, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import Session, declarative_base

# ==============================================================================
# 1. MODELS (Database Schema)
# ==============================================================================
Base = declarative_base()

class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(36), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    key_prefix = Column(String(12), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    is_active = Column(Boolean, default=True)

# ==============================================================================
# 2. SCHEMAS (Pydantic Models)
# ==============================================================================
class CreateAPIKeyRequest(BaseModel):
    name: str  # Ex: "Integração ERP", "Webhook RD Station"

class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    api_key: str  # Exibida APENAS nesta resposta
    created_at: datetime

    class Config:
        from_attributes = True

# Dummy Auth Dependency (Substitua pela sua implementação real de JWT / Contexto de Tenant)
class CurrentUser(BaseModel):
    id: str
    tenant_id: str

def get_current_user() -> CurrentUser:
    # Em produção, extrai e valida o token JWT do header Authorization
    return CurrentUser(id="user_123", tenant_id="tenant_456")

def get_db():
    # Dependency para injeção de sessão do banco de dados
    pass

# ==============================================================================
# 3. ROUTE IMPLEMENTATION
# ==============================================================================
router = APIRouter(prefix="/v1/integration-keys", tags=["Integration Keys"])

def generate_secure_api_key(environment_prefix: str = "sk_live_") -> tuple[str, str, str]:
    """
    Gera uma API key segura no formato: sk_live_<32_bytes_hex>
    Retorna: (chave_completa, prefixo, hash_sha256)
    """
    raw_token = secrets.token_hex(32)
    full_key = f"{environment_prefix}{raw_token}"
    prefix = full_key[:12]
    key_hash = hashlib.sha256(full_key.encode('utf-8')).hexdigest()

    return full_key, prefix, key_hash


@router.post("/", response_model=APIKeyResponse, status_code=status.HTTP_201_CREATED)
def create_integration_key(
    payload: CreateAPIKeyRequest,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user)):
    """
    Gera uma nova chave de API para a empresa (tenant) autenticada.
    ATENÇÃO: A chave 'api_key' gerada só será exibida nesta resposta.
    """
    if not payload.name.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O nome da chave de integração é obrigatório."
        )

    # 1. Gerar os dados da nova chave
    full_key, key_prefix, key_hash = generate_secure_api_key()
    key_id = f"key_{secrets.token_hex(12)}"

    # 2. Instanciar o registro isolado pelo tenant_id
    new_api_key = APIKey(
        id=key_id,
        tenant_id=current_user.tenant_id,  # Garante o isolamento multi-tenant
        name=payload.name.strip(),
        key_hash=key_hash,
        key_prefix=key_prefix,
        is_active=True
    )

    # 3. Persistir na base de dados
    try:
        db.add(new_api_key)
        db.commit()
        db.refresh(new_api_key)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao salvar a chave de integração no banco de dados."
        )

    # 4. Retornar DTO de resposta contendo a chave em texto plano
    return APIKeyResponse(
        id=new_api_key.id,
        name=new_api_key.name,
        key_prefix=new_api_key.key_prefix,
        api_key=full_key,
        created_at=new_api_key.created_at
    )