import os
import uuid
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl
import httpx

# Configurações globais
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # Limite de 5MB
ALLOWED_MIME_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
}
STORAGE_BASE_DIR = "./media/tenants"

router = APIRouter(prefix="/api/v1/account", tags=["Account Management"])


# --- Schemas ---
class LogoUploadURLRequest(BaseModel):
    image_url: HttpUrl


class AccountResponse(BaseModel):
    id: str
    name: str
    logo_url: str


# --- Mocks e Dependências do SaaS ---
class TenantContext:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id


async def get_current_tenant() -> TenantContext:
    """
    Dependência responsável por extrair e validar o tenant autenticado via Token JWT.
    Garante que as operações fiquem restritas ao contexto da empresa consumidora.
    """
    # Em produção: extrair o tenant_id da session/JWT validado
    return TenantContext(tenant_id="tenant_12345")


# --- Endpoint ---
@router.post(
    "/logo/url",
    response_model=AccountResponse,
    status_code=status.HTTP_200_OK,
    summary="Atualiza o logotipo da empresa através de uma URL externa",)
async def update_logo_from_url(
    payload: LogoUploadURLRequest,
    current_tenant: Annotated[TenantContext, Depends(get_current_tenant)],):

    url = str(payload.image_url)

    # 1. Download do arquivo com validações de segurança
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            async with client.stream("GET", url) as response:
                if response.status_code != status.HTTP_200_OK:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Não foi possível baixar a imagem da URL informada.",
                    )

                # Validar Content-Type
                content_type = response.headers.get("content-type", "").lower().split(";")[0]
                if content_type not in ALLOWED_MIME_TYPES:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Formato de imagem inválido. Formatos aceitos: {', '.join(ALLOWED_MIME_TYPES.keys())}",
                    )

                # Validar Content-Length prévio se informado no header
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > MAX_FILE_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="O arquivo excede o limite máximo permitido de 5MB.",
                    )

                # 2. Leitura e salvamento do arquivo em pedaços (streaming)
                extension = ALLOWED_MIME_TYPES[content_type]
                filename = f"logo_{uuid.uuid4().hex}{extension}"

                # Garantir isolamento no storage por ID do tenant
                tenant_dir = os.path.join(STORAGE_BASE_DIR, current_tenant.tenant_id)
                os.makedirs(tenant_dir, exist_ok=True)
                file_path = os.path.join(tenant_dir, filename)

                downloaded_size = 0
                with open(file_path, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        downloaded_size += len(chunk)
                        if downloaded_size > MAX_FILE_SIZE_BYTES:
                            f.close()
                            if os.path.exists(file_path):
                                os.remove(file_path)
                            raise HTTPException(
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                detail="O arquivo excede o limite máximo permitido de 5MB.",
                            )
                        f.write(chunk)

    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Falha ao se conectar com o servidor da imagem.",
        )

    # 3. Montar a URL relativa ou pública do arquivo salvo
    saved_logo_url = f"/media/tenants/{current_tenant.tenant_id}/{filename}"

    # 4. Atualizar o registro da conta do tenant no Banco de Dados
    # Exemplo:
    # await db.execute(
    #     "UPDATE accounts SET logo_url = :logo_url WHERE id = :tenant_id",
    #     {"logo_url": saved_logo_url, "tenant_id": current_tenant.tenant_id}
    # )

    return AccountResponse(
        id=current_tenant.tenant_id,
        name="Empresa Exemplo",
        logo_url=saved_logo_url,
    )