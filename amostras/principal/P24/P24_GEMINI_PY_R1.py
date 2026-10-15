from enum import Enum
from typing import Dict, Any, Optional
import json
import yaml

from fastapi import FastAPI, Depends, File, UploadFile, HTTPException, status
from pydantic import BaseModel, Field, ValidationError

app = FastAPI(title="SaaS Multi-tenant Config API")


# ==============================================================================
# 1. MODELOS DE DADOS E VALIDAÇÃO DE CONFIGURAÇÃO (Pydantic)
# ==============================================================================

class ThemeEnum(str, Enum):
    LIGHT = "light"
    DARK = "dark"
    SYSTEM = "system"

class NotificationSettings(BaseModel):
    email_alerts: bool = True
    slack_webhook_url: Optional[str] = None

class TenantConfigPayload(BaseModel):
    """
    Esquema de validação para o arquivo de configuração enviado pelo cliente.
    """
    company_display_name: str = Field(..., min_length=2, max_length=100)
    theme: ThemeEnum = ThemeEnum.LIGHT
    timezone: str = "UTC"
    max_active_users: int = Field(..., gt=0)
    notifications: NotificationSettings = Field(default_factory=NotificationSettings)


# ==============================================================================
# 2. CONTEXTO E DADOS DO TENANT (Simulação do Tenant isolado por Middleware/JWT)
# ==============================================================================

class TenantContext(BaseModel):
    tenant_id: str
    company_name: str
    subscription_plan: str  # ex: 'basic', 'pro', 'enterprise'
    max_allowed_users_by_plan: int

def get_current_tenant() -> TenantContext:
    """
    Injeção de dependência que simula a extração e validação do Tenant ID
    a partir do token JWT ou header de contexto da requisição.
    """
    # Em produção, esses dados viriam da verificação do token JWT do usuário/m2m.
    return TenantContext(
        tenant_id="tenant_company_xyz_123",
        company_name="Acme Corp",
        subscription_plan="pro",
        max_allowed_users_by_plan=50
    )


# ==============================================================================
# 3. CAMADA DE SERVIÇO / REGRAS DE NEGÓCIO MULTI-TENANT
# ==============================================================================

class ConfigurationService:
    @staticmethod
    def parse_file_content(content: bytes, filename: str) -> Dict[str, Any]:
        """Lê e interpreta arquivos JSON ou YAML."""
        if filename.endswith(".json"):
            try:
                return json.loads(content.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as err:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Arquivo JSON inválido ou malformatado: {str(err)}"
                )
        elif filename.endswith((".yaml", ".yml")):
            try:
                return yaml.safe_load(content.decode("utf-8"))
            except (yaml.YAMLError, UnicodeDecodeError) as err:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Arquivo YAML inválido ou malformatado: {str(err)}"
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Formato de arquivo não suportado. Envie um arquivo .json ou .yaml"
            )

    @staticmethod
    def validate_plan_limits(config: TenantConfigPayload, tenant: TenantContext):
        """Valida se as configurações não violam os limites do plano do cliente."""
        if config.max_active_users > tenant.max_allowed_users_by_plan:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"O número de usuários configurado ({config.max_active_users}) excede o "
                    f"limite do plano '{tenant.subscription_plan}' ({tenant.max_allowed_users_by_plan})."
                )
            )

    @staticmethod
    def apply_tenant_configuration(tenant_id: str, config: TenantConfigPayload) -> Dict[str, Any]:
        """
        Aplica os parâmetros no banco de dados isolando explicitamente pelo tenant_id.
        """
        # Exemplo hipotético de update no banco com garantia de isolamento multilocatário:
        # db.query(TenantSettings).filter(TenantSettings.tenant_id == tenant_id).update(config.model_dump())

        return {
            "status": "applied",
            "tenant_id": tenant_id,
            "applied_config": config.model_dump()
        }


# ==============================================================================
# 4. ROTA DA API
# ==============================================================================

@app.post(
    "/api/v1/settings/upload-config",
    status_code=status.HTTP_200_OK,
    summary="Aplica arquivo de configuração do Tenant",
    description="Recebe um arquivo .json ou .yaml com as configurações da empresa, valida os parâmetros contra o plano de assinatura e atualiza a conta.")
async def upload_tenant_config(
    file: UploadFile = File(...),
    current_tenant: TenantContext = Depends(get_current_tenant)):
    # 1. Leitura do conteúdo do arquivo enviado
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O arquivo enviado está vazio."
        )

    # 2. Parsing sintático (JSON / YAML)
    raw_data = ConfigurationService.parse_file_content(file_bytes, file.filename or "")

    # 3. Validação de esquema/tipos com Pydantic
    try:
        config_payload = TenantConfigPayload(**raw_data)
    except ValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Falha de validação no esquema da configuração", "errors": err.errors()}
        )

    # 4. Validação de regras de negócio (Regra do Plano SaaS)
    ConfigurationService.validate_plan_limits(config_payload, current_tenant)

    # 5. Persistência dos dados isolados por Tenant ID
    result = ConfigurationService.apply_tenant_configuration(
        tenant_id=current_tenant.tenant_id,
        config=config_payload
    )

    return {
        "message": "Configurações aplicadas com sucesso.",
        "tenant_id": current_tenant.tenant_id,
        "details": result
    }