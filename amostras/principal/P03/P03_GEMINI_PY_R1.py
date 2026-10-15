import io
import mimetypes
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
import httpx
from PIL import Image, ImageError
from pydantic import BaseModel, HttpUrl

# --- Configurações e Modelos ---

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # Limite de 2 MB
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/webp"}
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}

router = APIRouter(prefix="/account", tags=["Account Management"])


class LogoUploadURLRequest(BaseModel):
    image_url: HttpUrl


class CurrentUser(BaseModel):
    id: str
    tenant_id: str  # ID da empresa/locatário cliente
    role: str


# --- Dependências Fake (Substituir pela lógica real do sistema) ---


async def get_current_user() -> CurrentUser:
    """Injeta e valida o usuário autenticado a partir do token/sessão."""
    return CurrentUser(id="usr_123", tenant_id="tenant_abc456", role="admin")


def get_storage_client():
    """Retorna a instância do cliente de Object Storage (ex: AWS S3, MinIO, GCP Storage)."""
    # Exemplo mock/interface do S3
    class StorageClient:
        def upload_file(self, content: bytes, destination_key: str, content_type: str) -> str:
            # Em produção: self.s3.put_object(...)
            return f"https://cdn.saasplatform.com/{destination_key}"

    return StorageClient()


# --- Auxiliares de Segurança e Validação ---


def validate_image_bytes(content: bytes) -> str:
    """Valida o cabeçalho real do arquivo usando Pillow para evitar bypass de Content-Type."""
    try:
        with Image.open(io.BytesIO(content)) as img:
            img.verify()
            fmt = img.format.lower() if img.format else ""

            # Mapeamento do formato retornado pelo PIL para MIME Type
            mime_mapping = {
                "jpeg": "image/jpeg",
                "png": "image/png",
                "webp": "image/webp",
            }
            mime_type = mime_mapping.get(fmt)

            if not mime_type or mime_type not in ALLOWED_MIME_TYPES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Formato de imagem não suportado. Use PNG, JPEG ou WebP."
                )
            return mime_type
    except ImageError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O arquivo baixado não é uma imagem válida."
        )


# --- Rota de API ---


@router.post("/logo/from-url", status_code=status.HTTP_200_OK)
async def update_account_logo_from_url(
    payload: LogoUploadURLRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    storage: Annotated[object, Depends(get_storage_client)],):
    """
    Recebe a URL de uma imagem, faz o download seguro e salva como o logotipo oficial do Tenant.
    """
    url_str = str(payload.image_url)

    # 1. Download assíncrono com limites rígidos de timeout e tamanho
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=3.0),
            follow_redirects=True,
            max_redirects=3,
        ) as client:
            async with client.stream("GET", url_str) as response:
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Não foi possível baixar a imagem da URL fornecida.",
                    )

                # Verificar cabeçalho Content-Length prévio se presente
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_FILE_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="O arquivo excede o tamanho máximo permitido de 2MB.",
                    )

                # Leitura em chunks para evitar estouro de memória (OOM)
                buffer = bytearray()
                async for chunk in response.aiter_bytes():
                    buffer.extend(chunk)
                    if len(buffer) > MAX_FILE_SIZE_BYTES:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="O arquivo excede o tamanho máximo permitido de 2MB.",
                        )

                image_content = bytes(buffer)

    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Falha ao se conectar com a URL informada.",
        )

    # 2. Validação da integridade e do formato da imagem
    detected_mime_type = validate_image_bytes(image_content)
    file_extension = mimetypes.guess_extension(detected_mime_type) or ".png"

    # 3. Isolamento Multitenant no Storage
    # Garante que os arquivos do tenant fiquem isolados em sua respectiva estrutura de pastas/chaves
    storage_key = f"tenants/{current_user.tenant_id}/assets/logo{file_extension}"

    # 4. Upload para o Object Storage (S3 / GCP / Azure / MinIO)
    try:
        public_logo_url = storage.upload_file(
            content=image_content,
            destination_key=storage_key,
            content_type=detected_mime_type,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao salvar o arquivo no storage.",
        ) from exc

    # 5. Atualização do registro do Tenant na base de dados
    # ex: await tenant_repository.update_logo(tenant_id=current_user.tenant_id, logo_url=public_logo_url)

    return {
        "message": "Logotipo atualizado com sucesso.",
        "tenant_id": current_user.tenant_id,
        "logo_url": public_logo_url,
    }