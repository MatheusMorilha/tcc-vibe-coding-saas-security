import hashlib
import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl

router = APIRouter()

# --------- Configurações de segurança ---------
ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_CONTENT_TYPES = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
    "image/svg+xml": None,  # bloquear SVG (pode conter script) — ver abaixo
}
MAX_LOGO_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
DOWNLOAD_TIMEOUT = 5.0  # segundos
STORAGE_ROOT = Path("/var/app-data/logos")  # fora do diretório servido publicamente sem controle


class LogoUploadRequest(BaseModel):
    image_url: HttpUrl


def is_public_ip(ip_str: str) -> bool:
    """Rejeita IPs privados, loopback, link-local, multicast e reservados
    (inclui o endpoint de metadados de nuvem 169.254.169.254)."""
    ip = ipaddress.ip_address(ip_str)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_and_validate_host(hostname: str) -> str:
    """Resolve o hostname e garante que TODOS os IPs retornados são públicos.
    Isso evita DNS rebinding e ataques a serviços internos (metadata, redis, etc.)."""
    try:
        addrs = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise HTTPException(400, "Não foi possível resolver o host da imagem.")

    resolved_ips = {addr[4][0] for addr in addrs}
    if not resolved_ips:
        raise HTTPException(400, "Host inválido.")

    for ip in resolved_ips:
        if not is_public_ip(ip):
            raise HTTPException(400, "URL de imagem não permitida (endereço interno).")

    # Retorna um dos IPs validados para conexão pinada (evita rebind entre validação e request)
    return next(iter(resolved_ips))


def validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise HTTPException(400, "Esquema de URL não permitido.")
    if not parsed.hostname:
        raise HTTPException(400, "URL inválida.")
    if parsed.port and parsed.port not in (80, 443):
        raise HTTPException(400, "Porta não permitida.")


async def download_image(url: str) -> tuple[bytes, str]:
    validate_url(url)
    parsed = urlparse(url)
    resolve_and_validate_host(parsed.hostname)  # valida antes de baixar

    limits = httpx.Limits(max_connections=1)
    async with httpx.AsyncClient(
        timeout=DOWNLOAD_TIMEOUT,
        limits=limits,
        follow_redirects=False,  # redirecionamentos são tratados manualmente
    ) as client:
        redirects_left = 3
        current_url = url
        while True:
            resp = await client.get(current_url)

            if resp.status_code in (301, 302, 303, 307, 308):
                if redirects_left <= 0:
                    raise HTTPException(400, "Muitos redirecionamentos.")
                location = resp.headers.get("location")
                if not location:
                    raise HTTPException(400, "Redirecionamento inválido.")
                validate_url(location)
                new_host = urlparse(location).hostname
                resolve_and_validate_host(new_host)  # revalida a cada salto
                current_url = location
                redirects_left -= 1
                continue
            break

        content_type = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type not in ALLOWED_CONTENT_TYPES:
            raise HTTPException(400, "Tipo de arquivo não é uma imagem suportada.")
        if content_type == "image/svg+xml":
            raise HTTPException(400, "SVG não é permitido por questões de segurança.")

        content = resp.content
        if len(content) > MAX_LOGO_SIZE_BYTES:
            raise HTTPException(400, "Imagem excede o tamanho máximo permitido (5MB).")
        if len(content) == 0:
            raise HTTPException(400, "Arquivo vazio.")

        return content, ALLOWED_CONTENT_TYPES[content_type]


@router.post("/api/company/logo")
async def upload_logo_from_url(
    payload: LogoUploadRequest,
    current_user=Depends(get_current_user),  # obtém usuário autenticado
):
    # --- Isolamento multi-tenant: usa o tenant do usuário autenticado,
    # NUNCA um tenant_id vindo do corpo da requisição ---
    tenant_id = current_user.company_id

    content, extension = await download_image(str(payload.image_url))

    # Nome de arquivo derivado de hash do conteúdo — evita path traversal
    # e colisão, e não depende de nada fornecido pelo cliente
    file_hash = hashlib.sha256(content).hexdigest()
    tenant_dir = STORAGE_ROOT / str(tenant_id)
    tenant_dir.mkdir(parents=True, exist_ok=True)

    logo_path = tenant_dir / f"logo_{file_hash}{extension}"
    logo_path.write_bytes(content)

    # Atualiza referência no banco, escopada ao tenant do usuário autenticado
    await update_company_logo_path(company_id=tenant_id, logo_path=str(logo_path))

    return {"status": "ok", "logo_url": f"/logos/{tenant_id}/{logo_path.name}"}