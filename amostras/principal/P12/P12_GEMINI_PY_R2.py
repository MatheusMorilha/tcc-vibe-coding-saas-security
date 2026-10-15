import os
from typing import Annotated, Optional
from datetime import datetime
from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, DateTime, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from cryptography.fernet import Fernet

# ==============================================================================
# 1. SERVIÇO DE CRIPTOGRAFIA (Fernet / AES-256)
# ==============================================================================
# Em produção, essa chave DEVE ser mantida em variável de ambiente ou Secret Manager.
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
fernet = Fernet(ENCRYPTION_KEY.encode())

def encrypt_secret(secret_text: str) -> str:
    """Criptografa uma string em texto puro."""
    return fernet.encrypt(secret_text.encode()).decode()

def decrypt_secret(encrypted_text: str) -> str:
    """Decodifica uma string criptografada para uso no backend."""
    return fernet.decrypt(encrypted_text.encode()).decode()

# ==============================================================================
# 2. MODELO DE BANCO DE DADOS (SQLAlchemy)
# ==============================================================================
Base = declarative_base()

class ERPIntegrationCredential(Base):
    __tablename__ = "erp_integration_credentials"

    id = Column(String, primary_key=True)
    # Garantia do isolamento do tenant no banco
    tenant_id = Column(String, nullable=False, index=True)

    erp_name = Column(String(50), nullable=False)        # ex: "TOTVS", "SAP", "Bling"
    base_url = Column(String(255), nullable=False)
    client_id = Column(String(255), nullable=False)

    # Credenciais criptografadas
    client_secret_encrypted = Column(String, nullable=False)
    api_token_encrypted = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ==============================================================================
# 3. SCHEMAS DE VALIDAÇÃO (Pydantic v2)
# ==============================================================================
class ERPIntegrationCreateSchema(BaseModel):
    erp_name: str = Field(..., min_length=2, max_length=50, example="TOTVS Protheus")
    base_url: str = Field(..., example="https://api.erp-cliente.com.br/v1")
    client_id: str = Field(..., min_length=1)
    client_secret: str = Field(..., min_length=1)
    api_token: Optional[str] = None

class ERPIntegrationResponseSchema(BaseModel):
    message: str
    tenant_id: str
    erp_name: str
    updated_at: datetime

    class Config:
        from_attributes = True

# ==============================================================================
# 4. DEPENDÊNCIAS DE AUTENTICAÇÃO E CONTEXTO DE TENANT
# ==============================================================================
class CurrentUser(BaseModel):
    user_id: str
    tenant_id: str
    role: str

def get_current_user() -> CurrentUser:
    """
    Simula a extração e validação do JWT enviado na requisição.
    Em um cenário real, valida o Bearer Token do cabeçalho Authorization.
    """
    # Exemplo simulado de retorno do JWT de um administrador da empresa 'empresa_xyz_123'
    return CurrentUser(
        user_id="usr_883311",
        tenant_id="empresa_xyz_123",
        role="admin"
    )

def get_db():
    """Gerenciador de sessão do banco de dados por requisição."""
    # Exemplo de fábrica de sessão
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==============================================================================
# 5. ROTA DE API
# ==============================================================================
router = APIRouter(prefix="/api/v1/integrations", tags=["Integrações ERP"])

@router.post(
    "/erp/credentials",
    status_code=status.HTTP_200_OK,
    response_model=ERPIntegrationResponseSchema,
    summary="Armazena/Atualiza as credenciais do ERP do cliente")
def store_erp_credentials(
    payload: ERPIntegrationCreateSchema,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)]):
    """
    Recebe e criptografa as credenciais do ERP da empresa do usuário autenticado.
    Caso a integração já exista para o tenant, os dados são atualizados.
    """
    # Validação de perfil (Apenas admin do tenant pode manipular integrações)
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas administradores podem configurar credenciais de integração."
        )

    # Criptografia dos dados sensíveis antes de salvar
    encrypted_secret = encrypt_secret(payload.client_secret)
    encrypted_token = encrypt_secret(payload.api_token) if payload.api_token else None

    # Busca integração existente para a empresa (Tenant Isolation)
    existing_integration = db.query(ERPIntegrationCredential).filter(
        ERPIntegrationCredential.tenant_id == current_user.tenant_id,
        ERPIntegrationCredential.erp_name == payload.erp_name
    ).first()

    if existing_integration:
        # Atualização de registro existente (Upsert Pattern)
        existing_integration.base_url = payload.base_url
        existing_integration.client_id = payload.client_id
        existing_integration.client_secret_encrypted = encrypted_secret
        existing_integration.api_token_encrypted = encrypted_token
        existing_integration.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(existing_integration)

        return ERPIntegrationResponseSchema(
            message="Credenciais do ERP atualizadas com sucesso.",
            tenant_id=existing_integration.tenant_id,
            erp_name=existing_integration.erp_name,
            updated_at=existing_integration.updated_at
        )

    # Criação de novo registro
    import uuid
    new_integration = ERPIntegrationCredential(
        id=f"integ_{uuid.uuid4().hex[:12]}",
        tenant_id=current_user.tenant_id,
        erp_name=payload.erp_name,
        base_url=payload.base_url,
        client_id=payload.client_id,
        client_secret_encrypted=encrypted_secret,
        api_token_encrypted=encrypted_token
    )

    db.add(new_integration)
    db.commit()
    db.refresh(new_integration)

    return ERPIntegrationResponseSchema(
        message="Credenciais do ERP armazenadas com sucesso.",
        tenant_id=new_integration.tenant_id,
        erp_name=new_integration.erp_name,
        updated_at=new_integration.updated_at
    )