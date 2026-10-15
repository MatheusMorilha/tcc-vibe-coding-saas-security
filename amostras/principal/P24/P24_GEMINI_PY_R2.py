import json
import yaml
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

# -----------------------------------------------------------------------------
# Schemas de Validação (DTOs)
# -----------------------------------------------------------------------------
class TenantConfigSchema(BaseModel):
    """
    Define e valida a estrutura dos parâmetros de configuração aceitos.
    """
    theme: Optional[str] = Field(None, example="dark")
    notifications_enabled: Optional[bool] = Field(True, example=True)
    max_users_limit: Optional[int] = Field(None, ge=1, example=50)
    integrations: Optional[Dict[str, Any]] = Field(default_factory=dict)

class UserContext(BaseModel):
    """
    Representa o usuário autenticado e o locatário ao qual ele pertence.
    """
    user_id: str
    tenant_id: str
    role: str

# -----------------------------------------------------------------------------
# Dependência de Autenticação / Multi-tenancy
# -----------------------------------------------------------------------------
async def get_current_user() -> UserContext:
    """
    Simulação do middleware/dependência de autenticação.
    Injeta o contexto do usuário extraído do JWT Token.
    """
    # Em produção, este método decodificaria o header Authorization: Bearer <token>
    return UserContext(
        user_id="usr_12345",
        tenant_id="tenant_company_abc",
        role="admin"
    )