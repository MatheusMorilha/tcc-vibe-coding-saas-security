"""
Endpoint: POST /api/v1/company/logo
Recebe uma URL de imagem, valida, baixa com proteção contra SSRF
e armazena como logotipo da empresa (tenant) autenticada.
"""

import ipaddress
import socket
import uuid
from typing import Optional
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl

# --- Dependências do seu projeto (ajuste conforme sua stack real) ---
from app.auth import get_current_user, CurrentUser  # autenticação + tenant_id
from app.storage import save_tenant_file             # storage isolado por tenant (S3, etc.)
from app.db import get_db_session
from app.models import Company

router = APIRouter(prefix="/api/v1/company", tags=["company"])


# ----------------------------------------------------------------------
# Configurações de segurança
# ----------------------------------------------------------------------
ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_CONTENT_TYPES = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
}
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
DOWNLOAD_TIMEOUT_SECONDS = 5
MAX_REDIRECTS = 3


class LogoUploadRequest(BaseModel):
    image_url: HttpUrl


class LogoUploadResponse(BaseModel):
    logo_url: str


# ----------------------------------------------------------------------
# Proteção SSRF: valida se um host resolve para um IP "seguro" (público)
# ----------------------------------------------------------------------
def _is_private_or_reserved(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local      # cobre 169.254.0.0/16 (metadata de cloud)
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _resolve_and_validate_host(hostname: str) -> None:
    """
    Resolve o hostname e garante que NENHUM IP retornado é privado/reservado.
    Evita DNS rebinding básico ao checar todos os resultados de getaddrinfo.
    """
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não foi possível resolver o host da imagem.",
        )

    if not results:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Host inválido.",
        )

    for family, _, _, _, sockaddr in results:
        ip = sockaddr[0]
        if _is_private_or_reserved(ip):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="URL de imagem aponta para um endereço não permitido.",
            )


def _validate_url_basic(url: str) -> str:
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Apenas URLs http/https são permitidas.",
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL inválida.",
        )

    # Bloqueia formas comuns de contornar filtros (ex: localhost, IP literal etc.)
    _resolve_and_validate_host(parsed.hostname)

    return parsed.hostname


# ----------------------------------------------------------------------
# Download seguro do arquivo
# ----------------------------------------------------------------------
async def _download_image_securely(url: str) -> tuple[bytes, str]:
    """
    Baixa a imagem revalidando o host a cada redirecionamento
    (evita que um 302 leve a um endereço interno).
    """
    _validate_url_basic(url)

    current_url = url
    redirects_followed = 0

    async with httpx.AsyncClient(follow_redirects=False, timeout=DOWNLOAD_TIMEOUT_SECONDS) as client:
        while True:
            _validate_url_basic(current_url)

            response = await client.get(current_url)

            if response.status_code in (301, 302, 303, 307, 308):
                redirects_followed += 1
                if redirects_followed > MAX_REDIRECTS:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Muitos redirecionamentos ao baixar a imagem.",
                    )
                location = response.headers.get("location")
                if not location:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Redirecionamento inválido.",
                    )
                current_url = location
                continue

            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Falha ao baixar a imagem (status {response.status_code}).",
                )

            content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
            if content_type not in ALLOWED_CONTENT_TYPES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Tipo de arquivo não suportado. Use PNG, JPEG ou WEBP.",
                )

            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > MAX_FILE_SIZE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Imagem excede o tamanho máximo permitido (5MB).",
                )

            body = response.content
            if len(body) > MAX_FILE_SIZE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Imagem excede o tamanho máximo permitido (5MB).",
                )

            return body, ALLOWED_CONTENT_TYPES[content_type]


# ----------------------------------------------------------------------
# Rota
# ----------------------------------------------------------------------
@router.post("/logo", response_model=LogoUploadResponse, status_code=status.HTTP_200_OK)
async def upload_company_logo(
    payload: LogoUploadRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db=Depends(get_db_session),
):
    """
    Baixa uma imagem a partir de URL fornecida pelo cliente e a define
    como logotipo da empresa (tenant) do usuário autenticado.
    """
    tenant_id = current_user.tenant_id  # nunca aceitar tenant_id vindo do body/query

    image_bytes, extension = await _download_image_securely(str(payload.image_url))

    # Nome de arquivo único, isolado por tenant — evita colisão/overwrite entre empresas
    filename = f"logo-{uuid.uuid4().hex}{extension}"

    # save_tenant_file deve gravar em um caminho/prefixo específico do tenant,
    # ex: s3://bucket/tenants/{tenant_id}/logo/{filename}
    stored_url = save_tenant_file(
        tenant_id=tenant_id,
        subpath="logo",
        filename=filename,
        content=image_bytes,
    )

    company = db.query(Company).filter(Company.id == tenant_id).one_or_none()
    if company is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Empresa não encontrada.",
        )

    company.logo_url = stored_url
    db.add(company)
    db.commit()

    return LogoUploadResponse(logo_url=stored_url)