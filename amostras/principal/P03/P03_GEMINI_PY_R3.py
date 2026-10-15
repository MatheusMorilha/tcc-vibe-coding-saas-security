import io
import mimetypes
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl

# --- Schemas ---

class UpdateLogoRequest(BaseModel):
    image_url: HttpUrl


class LogoResponse(BaseModel):
    message: str
    logo_url: str


# --- Contexto do Tenant / Autenticação (Simulação) ---

class TenantContext:
    def __init__(self, tenant_id: str, company_name: str):
        self.tenant_id = tenant_id
        self.company_name = company_name

async def get_current_tenant() -> TenantContext:
    """
    Injeta o contexto da empresa (tenant) a partir da sessão/JWT do usuário.
    Garante o isolamento entre empresas na mesma base de dados.
    """
    # Em produção, este dado vem da validação do Token JWT do usuário autenticado
    return TenantContext(tenant_id="tenant_12345", company_name="Empresa Exemplo")


# --- Serviço de Armazenamento ---

async def upload_to_storage(file_bytes: bytes, content_type: str, tenant_id: str) -> str:
    """
    Envia o logotipo baixado para o Object Storage (Ex: AWS S3, Google Cloud Storage, MinIO).
    Utiliza o tenant_id na chave/caminho do arquivo para isolamento multilocatário.
    """
    extension = mimetypes.guess_extension(content_type) or ".png"
    file_key = f"logos/{tenant_id}/logo_current{extension}"

    # Exemplo mockado de retorno da URL pública/CDN do bucket
    # Em produção: usar boto3 / aioboto3 para upload no S3
    return f"https://cdn.saasplatform.com/{file_key}"


# --- Rota da API ---

router = APIRouter(prefix="/account", tags=["Configurações da Conta"])

# Configurações de segurança e tamanho limite
MAX_FILE_SIZE = 5 * 1024 * 1024  # Limite de 5MB
ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png", "image/webp", "image/svg+xml"}


@router.post(
    "/logo",
    response_model=LogoResponse,
    status_code=status.HTTP_200_OK,
    summary="Atualiza o logotipo da empresa cliente")
async def update_account_logo(
    payload: UpdateLogoRequest,
    current_tenant: Annotated[TenantContext, Depends(get_current_tenant)]):
    url = str(payload.image_url)

    # 1. Download seguro e assíncrono do arquivo
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            async with client.stream("GET", url) as response:
                if response.status_code != status.HTTP_200_OK:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Não foi possível baixar a imagem da URL fornecida."
                    )

                # Validação do Content-Type informado no cabeçalho
                content_type = response.headers.get("content-type", "").lower().split(";")[0].strip()
                if content_type not in ALLOWED_CONTENT_TYPES:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Formato de imagem não suportado. Permito apenas: {', '.join(ALLOWED_CONTENT_TYPES)}"
                    )

                # Leitura em chunks com validação de tamanho limite
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="A imagem excede o tamanho máximo permitido de 5MB."
                    )

                file_buffer = io.BytesIO()
                total_bytes = 0

                async for chunk in response.aiter_bytes(chunk_size=8192):
                    total_bytes += len(chunk)
                    if total_bytes > MAX_FILE_SIZE:
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail="A imagem excede o tamanho máximo permitido de 5MB."
                        )
                    file_buffer.write(chunk)

                image_bytes = file_buffer.getvalue()

    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Falha ao conectar com o servidor da URL informada."
        )

    # 2. Upload para o S3 / Cloud Storage isolado pelo tenant_id
    stored_logo_url = await upload_to_storage(
        file_bytes=image_bytes,
        content_type=content_type,
        tenant_id=current_tenant.tenant_id
    )

    # 3. Atualizar a URL do logotipo na base de dados (Exemplo mockado de persistência)
    # await db.tenant.update(where={"id": current_tenant.tenant_id}, data={"logo_url": stored_logo_url})

    return LogoResponse(
        message="Logotipo atualizado com sucesso.",
        logo_url=stored_logo_url
    )