import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import Session, declarative_base

Base = declarative_base()

# ==========================================
# 1. MODELO DE BANCO DE DADOS (SQLAlchemy)
# ==========================================
class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    key_prefix = Column(String(12), nullable=False)  # Ex: "sk_live_a1b2" para identificação rápida
    key_hash = Column(String(64), nullable=False, unique=True, index=True)  # Hash SHA-256 da chave
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)


# ==========================================
# 2. SCHEMAS DE REQUISIÇÃO E RESPOSTA (Pydantic)
# ==========================================
class CreateApiKeyRequest(BaseModel):
    name: str  # Nome identificador da chave (ex: "Integração CRM")

class ApiKeyCreatedResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    api_key: str  # Exibida ÚNICA vez na criação
    created_at: datetime

    class Config:
        from_attributes = True


# ==========================================
# 3. MOCK DE DEPENDÊNCIAS (Injeção de Contexto)
# ==========================================
class UserContext:
    """Representa o usuário autenticado e o tenant extraído do Token JWT."""
    def __init__(self, user_id: int, tenant_id: int, role: str):
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.role = role

def get_current_user() -> UserContext:
    # Substituir pela lógica real de verificação do JWT
    return UserContext(user_id=10, tenant_id=42, role="admin")

def get_db():
    # Substituir pelo gerador de sessão do banco de dados real
    yield None


# ==========================================
# 4. ROTA DA API
# ==========================================
router = APIRouter(prefix="/api/v1/integration-keys", tags=["Integration Keys"])

@router.post("", response_model=ApiKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
def generate_integration_key(
    payload: CreateApiKeyRequest,
    current_user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db)):
    """
    Gera uma nova chave de API para o tenant autenticado.
    A chave original é retornada apenas nesta resposta e nunca é armazenada em texto plano.
    """
    # 1. Autorização: Apenas administradores do tenant podem criar chaves
    if current_user.role not in ["admin", "owner"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permissão insuficiente para gerar chaves de integração."
        )

    # 2. Gera um token seguro usando 'secrets'
    # Exemplo de formato: sk_live_32_caracteres_hex
    raw_secret = secrets.token_hex(24)
    api_key = f"sk_live_{raw_secret}"

    # 3. Prefixo para exibição/identificação e Hash SHA-256 para persistência
    key_prefix = api_key[:12]
    key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    # 4. Instancia e persiste no contexto do Tenant atual (Multitenancy via Column-level Isolation)
    new_key = ApiKey(
        tenant_id=current_user.tenant_id,
        name=payload.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        is_active=True
    )

    db.add(new_key)
    db.commit()
    db.refresh(new_key)

    # 5. Retorna a chave ao cliente (único momento em que 'api_key' é transmitida)
    return ApiKeyCreatedResponse(
        id=new_key.id,
        name=new_key.name,
        key_prefix=new_key.key_prefix,
        api_key=api_key,
        created_at=new_key.created_at
    )