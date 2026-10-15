import json
import yaml
from typing import Dict, Any
from fastapi import APIRoute, APIRouter, Depends, UploadFile, File, HTTPException, status
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session

# ==============================================================================
# 1. SCHEMAS DE VALIDAÇÃO (Pydantic)
# Define e valida os parâmetros permitidos no arquivo de configuração.
# ==============================================================================

class NotificationSettings(BaseModel):
    email_alerts: bool = True
    slack_webhook: str | None = None

class TenantConfigSchema(BaseModel):
    timezone: str = Field(default="UTC")
    language: str = Field(default="pt-BR")
    max_users_limit: int = Field(gt=0)
    notifications: NotificationSettings

    class Config:
        extra = "forbid"  # Impede a inserção de chaves não mapeadas/maliciosas


class UserPayload(BaseModel):
    user_id: str
    tenant_id: str
    role: str


# ==============================================================================
# 2. MIDDLEWARE / DEPENDÊNCIA DE AUTENTICAÇÃO
# Garante que o tenant_id venha estritamente do contexto autenticado.
# ==============================================================================

def get_current_user() -> UserPayload:
    """
    Simulação da extração e validação do Token JWT do cabeçalho Authorization.
    Em produção, valide a assinatura do JWT e extraia as claims.
    """
    # Exemplo de payload extraído com segurança do Token JWT
    return UserPayload(
        user_id="usr_98765",
        tenant_id="tenant_12345",
        role="admin"
    )

def get_db_session():
    """Dependência para injetar a sessão do banco de dados (Ex: SQLAlchemy/SQLModel)."""
    db = None  # Substituir pela sua Session Local
    try:
        yield db
    finally:
        pass


# ==============================================================================
# 3. ROTA DA API
# ==============================================================================

router = APIRouter(prefix="/v1/settings", tags=["Tenant Settings"])

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # Limite de 2MB

@router.post("/import", status_code=status.HTTP_200_OK)
async def import_tenant_configuration(
    file: UploadFile = File(...),
    current_user: UserPayload = Depends(get_current_user),
    db: Session = Depends(get_db_session)):
    """
    Recebe um arquivo de configuração (JSON ou YAML), valida o esquema
    e aplica as configurações à conta do tenant autenticado.
    """
    # A. Restrição de Acesso (RBAC)
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas administradores podem alterar as configurações da conta."
        )

    # B. Validação do tamanho do arquivo
    content_bytes = await file.read()
    if len(content_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="O arquivo excede o limite máximo permitido de 2MB."
        )

    # C. Parsing do Conteúdo (JSON ou YAML)
    parsed_content: Dict[str, Any] = {}
    filename = file.filename.lower() if file.filename else ""

    try:
        if filename.endswith(".json"):
            parsed_content = json.loads(content_bytes.decode("utf-8"))
        elif filename.endswith((".yaml", ".yml")):
            # safe_load evita execução remota de código (RCE) via YAML
            parsed_content = yaml.safe_load(content_bytes.decode("utf-8"))
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Formato de arquivo inválido. Envie um arquivo .json ou .yaml/.yml"
            )
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Sintaxe inválida no arquivo enviado: {str(exc)}"
        )

    # D. Validação Estrutural e de Tipagem via Pydantic
    try:
        validated_config = TenantConfigSchema(**parsed_content)
    except ValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Inconformidade no esquema do arquivo.", "errors": err.errors()}
        )

    # E. Aplicação Persistente no Banco de Dados com Isolamento Multi-tenant
    try:
        # IMPORTANTE: A query DEVE obrigatoriamente filtrar pelo tenant_id autenticado
        # Exemplo conceitual usando ORM:
        # tenant = db.query(Tenant).filter(Tenant.id == current_user.tenant_id).first()
        # if not tenant:
        #     raise HTTPException(status_code=404, detail="Tenant não encontrado.")
        #
        # tenant.settings = validated_config.model_dump()
        # db.commit()

        return {
            "status": "success",
            "message": "Configurações atualizadas com sucesso.",
            "tenant_id": current_user.tenant_id,
            "applied_settings": validated_config.model_dump()
        }

    except Exception as db_err:
        # db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao persistir as configurações no banco de dados."
        )