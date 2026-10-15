import os
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from cryptography.fernet import Fernet

router = APIRouter(prefix="/api/v1/integrations/erp", tags=["ERP Integration"])

# -----------------------------------------------------------------------------
# Configuração de Criptografia Simétrica (AES-128-CBC / HMAC via Fernet)
# Em produção, carregar via variável de ambiente ou Secret Manager
# -----------------------------------------------------------------------------
ENCRYPTION_KEY = os.getenv("ERP_ENCRYPTION_KEY", Fernet.generate_key().decode())
cipher_suite = Fernet(ENCRYPTION_KEY.encode())


# -----------------------------------------------------------------------------
# Schemas Pydantic (Validação de Entrada)
# -----------------------------------------------------------------------------
class ERPCredentialsSchema(BaseModel):
    erp_provider: str = Field(..., example="TOTVS", description="Nome do ERP (ex: TOTVS, SAP, Omie)")
    base_url: str = Field(..., example="https://api.erpcliente.com.br", description="URL base da API do ERP")
    api_key: Optional[str] = Field(None, description="Chave/Token de API, se aplicável")
    username: Optional[str] = Field(None, description="Usuário de autenticação")
    password: Optional[str] = Field(None, description="Senha ou Secret do ERP")

class IntegrationStatusResponse(BaseModel):
    message: str
    company_id: str
    erp_provider: str
    is_configured: bool


# -----------------------------------------------------------------------------
# Simulação de Injeção de Dependência para Autenticação e Contexto do Tenant
# -----------------------------------------------------------------------------
class CurrentUser:
    def __init__(self, user_id: str, company_id: str):
        self.user_id = user_id
        self.company_id = company_id

async def get_current_user() -> CurrentUser:
    """
    Simula a extração do usuário e do tenant a partir do JWT/Bearer Token.
    Garante o isolamento multi-tenant extraindo o company_id diretamente do token.
    """
    # Exemplo: Payload extraído do token autenticado
    return CurrentUser(user_id="usr_98765", company_id="comp_12345")


# -----------------------------------------------------------------------------
# Simulação da Camada de Banco de Dados (ORM / Repository)
# -----------------------------------------------------------------------------
async def save_credentials_to_db(
    company_id: str,
    erp_provider: str,
    base_url: str,
    encrypted_api_key: Optional[str],
    encrypted_username: Optional[str],
    encrypted_password: Optional[str]) -> None:
    """
    Simula o comando 'UPSERT' no banco PostgreSQL/MySQL compartilhado.
    Registra ou atualiza as credenciais criptografadas vinculadas ao `company_id`.
    """
    # Exemplo em SQL (com SQLAlchemy / Tortoise / SQLModel):
    # UPDATE tenant_erp_config SET base_url=..., encrypted_password=... WHERE company_id = company_id
    pass


# -----------------------------------------------------------------------------
# Funções Utilitárias de Criptografia
# -----------------------------------------------------------------------------
def encrypt_secret(secret: Optional[str]) -> Optional[str]:
    if not secret:
        return None
    return cipher_suite.encrypt(secret.encode()).decode()


# -----------------------------------------------------------------------------
# Endpoint de Armazenamento de Credenciais
# -----------------------------------------------------------------------------
@router.post(
    "/credentials",
    response_model=IntegrationStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Armazena credenciais criptografadas de integração com ERP")
async def store_erp_credentials(
    credentials: ERPCredentialsSchema,
    current_user: CurrentUser = Depends(get_current_user)):
    """
    Recebe as credenciais de acesso ao ERP do cliente, realiza a criptografia simétrica
    dos campos sensíveis e as persiste associando-as ao ID do tenant (company_id).
    """
    try:
        # 1. Criptografia dos dados sensíveis antes do armazenamento
        enc_api_key = encrypt_secret(credentials.api_key)
        enc_username = encrypt_secret(credentials.username)
        enc_password = encrypt_secret(credentials.password)

        # 2. Persistência isolada por Tenant (Tenant Context de 'current_user.company_id')
        await save_credentials_to_db(
            company_id=current_user.company_id,
            erp_provider=credentials.erp_provider,
            base_url=credentials.base_url,
            encrypted_api_key=enc_api_key,
            encrypted_username=enc_username,
            encrypted_password=enc_password
        )

        return IntegrationStatusResponse(
            message="Credenciais de integração com ERP salvas com sucesso.",
            company_id=current_user.company_id,
            erp_provider=credentials.erp_provider,
            is_configured=True
        )

    except Exception as e:
        # Evita expor detalhes internos do erro
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ocorreu um erro interno ao processar e armazenar as credenciais do ERP."
        )