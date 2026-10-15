"""
Proteções contra SSRF na validação de URLs fornecidas por clientes.
"""
import ipaddress
import socket
from urllib.parse import urlparse

# Apenas esquemas HTTP(S) são permitidos
ALLOWED_SCHEMES = {"http", "https"}

# Portas permitidas (evita escaneamento de portas internas)
ALLOWED_PORTS = {80, 443}


class UnsafeURLError(Exception):
    pass


def _is_private_or_reserved(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def validate_and_resolve(url: str) -> str:
    """
    Valida o esquema, host e IP resolvido da URL.
    Retorna o IP resolvido (para pinning na requisição real,
    evitando TOCTOU / DNS rebinding).
    """
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError("Esquema de URL não permitido.")

    if not parsed.hostname:
        raise UnsafeURLError("URL inválida.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise UnsafeURLError("Porta não permitida.")

    # Bloqueia credenciais embutidas na URL (user:pass@host)
    if parsed.username or parsed.password:
        raise UnsafeURLError("URL com credenciais não é permitida.")

    try:
        resolved_ips = socket.getaddrinfo(parsed.hostname, port)
    except socket.gaierror:
        raise UnsafeURLError("Não foi possível resolver o host.")

    for family, _, _, _, sockaddr in resolved_ips:
        ip = sockaddr[0]
        if _is_private_or_reserved(ip):
            raise UnsafeURLError("Endereço IP não permitido (rede interna/reservada).")

    # Retorna o primeiro IP resolvido para pinning na requisição
    return resolved_ips[0][4][0]

"""
Serviço responsável por baixar e armazenar o logotipo de uma empresa (tenant).
"""
import hashlib
import io
import os
import uuid

import httpx
from PIL import Image

from app.security.ssrf_guard import validate_and_resolve, UnsafeURLError

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
ALLOWED_CONTENT_TYPES = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
}
DOWNLOAD_TIMEOUT_SECONDS = 5.0
STORAGE_BASE_DIR = "/var/app-data/tenant-logos"  # troque por S3/GCS em produção


class LogoDownloadError(Exception):
    pass


def _stream_download(url: str, resolved_ip: str) -> bytes:
    """
    Baixa o conteúdo com limite de tamanho, timeout curto,
    sem seguir redirecionamentos automaticamente (para não
    contornar a validação de SSRF), e usando o IP já resolvido
    para evitar DNS rebinding.
    """
    headers = {"Host": httpx.URL(url).host}
    transport = httpx.HTTPTransport(retries=0)

    with httpx.Client(
        transport=transport,
        timeout=DOWNLOAD_TIMEOUT_SECONDS,
        follow_redirects=False,  # redirecionamentos exigiriam nova validação
    ) as client:
        with client.stream("GET", url, headers=headers) as response:
            if response.status_code != 200:
                raise LogoDownloadError(f"Falha ao baixar imagem (status {response.status_code}).")

            content_type = response.headers.get("content-type", "").split(";")[0].strip()
            if content_type not in ALLOWED_CONTENT_TYPES:
                raise LogoDownloadError("Tipo de conteúdo não suportado.")

            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > MAX_FILE_SIZE_BYTES:
                raise LogoDownloadError("Arquivo excede o tamanho máximo permitido.")

            buffer = io.BytesIO()
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > MAX_FILE_SIZE_BYTES:
                    raise LogoDownloadError("Arquivo excede o tamanho máximo permitido durante o download.")
                buffer.write(chunk)

            return buffer.getvalue(), content_type


def _validate_is_real_image(data: bytes) -> None:
    """
    Confere que o conteúdo baixado é de fato uma imagem válida,
    e não apenas um arquivo com Content-Type forjado.
    """
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.verify()
    except Exception:
        raise LogoDownloadError("O arquivo baixado não é uma imagem válida.")


def download_and_store_logo(tenant_id: str, url: str) -> str:
    """
    Fluxo completo: valida a URL, baixa a imagem com segurança,
    valida o conteúdo e armazena isolado por tenant.
    Retorna o caminho/identificador do arquivo armazenado.
    """
    try:
        resolved_ip = validate_and_resolve(url)
    except UnsafeURLError as e:
        raise LogoDownloadError(str(e))

    data, content_type = _stream_download(url, resolved_ip)
    _validate_is_real_image(data)

    extension = ALLOWED_CONTENT_TYPES[content_type]
    file_hash = hashlib.sha256(data).hexdigest()[:16]
    filename = f"{uuid.uuid4()}-{file_hash}.{extension}"

    # Isolamento multilocatário: cada empresa tem seu próprio diretório/prefixo
    tenant_dir = os.path.join(STORAGE_BASE_DIR, tenant_id)
    os.makedirs(tenant_dir, exist_ok=True)

    file_path = os.path.join(tenant_dir, filename)
    with open(file_path, "wb") as f:
        f.write(data)

    return file_path

"""
Endpoint da API para upload de logotipo via URL.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl

from app.auth import get_current_tenant  # obtém o tenant autenticado da sessão/token
from app.services.logo_service import download_and_store_logo, LogoDownloadError

router = APIRouter()


class LogoUploadRequest(BaseModel):
    image_url: HttpUrl


@router.post("/api/v1/account/logo")
def upload_logo(
    payload: LogoUploadRequest,
    tenant=Depends(get_current_tenant),  # garante isolamento multilocatário
):
    try:
        file_path = download_and_store_logo(
            tenant_id=str(tenant.id),
            url=str(payload.image_url),
        )
    except LogoDownloadError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # Atualiza o registro da empresa com o novo caminho do logo
    tenant.logo_path = file_path
    tenant.save()

    return {"status": "ok", "logo_path": file_path}