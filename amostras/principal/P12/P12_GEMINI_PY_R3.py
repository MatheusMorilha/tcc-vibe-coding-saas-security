import os
from typing import Dict, Any, Optional
from fastapi import FastAPI, Depends, HTTPException, status, Header
from pydantic import BaseModel, Field
from cryptography.fernet import Fernet

app = FastAPI(title="SaaS ERP Integration API")

# --- GERENCIAMENTO DE CHAVE DE CRIPTOGRAFIA ---
# Em produção, carregar via variável de ambiente ou KMS (AWS KMS, HashiCorp Vault)
# Exemplo de geração de chave: Fernet.generate_key().decode()
ENCRYPTION_KEY = os.getenv("ERP_ENCRYPTION_KEY", Fernet.generate_key().decode())
cipher_suite = Fernet(ENCRYPTION_KEY.encode())


# --- MODELOS PYDANTIC ---
class ERPCredentialsPayload(BaseModel):
    erp_type: str = Field(..., example="TOTVS_PROTHEUS", description="Identificador do ERP")
    api_url: str = Field(..., example="https://erp.cliente.com.br/api/v1", description="URL base da API do ERP")
    client_id: str = Field(..., example="saas_integration_id")
    client_secret: str = Field(..., example="secret_key_123")
    additional_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Parâmetros adicionais específicos do ERP (ex: empresa, filial, token de ambiente)"
    )


class ERPIntegrationResponse(BaseModel):
    message: str
    tenant_id: str
    erp_type: str
    status: str


# --- SIMULAÇÃO DE BANCO DE DADOS E CONTEXTO MULTITENANT ---
# MOCK DATABASE (Em produção, utilize SQLAlchemy, SQLModel, etc.)
db_mock: Dict[str, Dict[str, Any]] = {}


def get_current_tenant_id(x_tenant_id: Optional[str] = Header(None)) -> str:
    """
    Middleware/Injeção de Dependência para extrair e validar o tenant_id.
    Em produção, este valor viria do Token JWT (claim) e não diretamente do Header.
    """
    if not x_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header 'X-Tenant-ID' ausente. Acesso negado."
        )
    return x_tenant_id


# --- ROTAS DA API ---
@app.post(
    "/api/v1/integrations/erp/credentials",
    response_model=ERPIntegrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Armazena credenciais criptografadas do ERP da empresa",
    tags=["Integração ERP"])
async def store_erp_credentials(
    payload: ERPCredentialsPayload,
    tenant_id: str = Depends(get_current_tenant_id)):

    try:
        # 1. Serializar dados sensíveis para criptografia
        raw_credentials = {
            "client_id": payload.client_id,
            "client_secret": payload.client_secret,
            "additional_config": payload.additional_config or {}
        }

        # Converte para string/bytes antes de criptografar
        import json
        json_data = json.dumps(raw_credentials).encode('utf-8')

        # 2. Criptografar as credenciais
        encrypted_data = cipher_suite.encrypt(json_data).decode('utf-8')

        # 3. Persistir no banco de dados isolado por tenant_id
        # Garante que cada empresa sobrescreva/atualize apenas suas próprias credenciais
        db_mock[tenant_id] = {
            "tenant_id": tenant_id,
            "erp_type": payload.erp_type,
            "api_url": payload.api_url,
            "encrypted_credentials": encrypted_data,
            "status": "CONFIGURED"
        }

        return ERPIntegrationResponse(
            message="Credenciais do ERP armazenadas com sucesso.",
            tenant_id=tenant_id,
            erp_type=payload.erp_type,
            status="CONFIGURED"
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao criptografar e salvar as credenciais."
        )


# --- FUNÇÃO AUXILIAR PARA A ROTINA DE INTEGRAÇÃO (BACKGROUND JOBS) ---
def get_decrypted_erp_credentials(tenant_id: str) -> Dict[str, Any]:
    """
    Método utilitário para ser chamado nos Workers/Cron Jobs de integração backend.
    """
    tenant_data = db_mock.get(tenant_id)
    if not tenant_data:
        raise ValueError(f"Credenciais não encontradas para o tenant: {tenant_id}")

    # Decodificar e descriptografar
    encrypted_bytes = tenant_data["encrypted_credentials"].encode('utf-8')
    decrypted_bytes = cipher_suite.decrypt(encrypted_bytes)

    import json
    credentials = json.loads(decrypted_bytes.decode('utf-8'))

    return {
        "erp_type": tenant_data["erp_type"],
        "api_url": tenant_data["api_url"],
        **credentials
    }