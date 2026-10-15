from __future__ import annotations

import hashlib
import ipaddress
import socket
from pathlibimport Path
from urllib.parseimport urlparse

import httpx
from fastapiimport Depends, FastAPI, HTTPException, status
from pydanticimport BaseModel, HttpUrl
from sqlalchemyimport String, update
from sqlalchemy.ormimport Session

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

app= FastAPI()

LOGO_DIRECTORY= Path("/var/lib/my-saas/logos")
MAX_LOGO_SIZE= 5 * 1024 * 1024  # 5 MB

ALLOWED_CONTENT_TYPES= {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}

LOGO_DIRECTORY.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Modelos / dependências ilustrativos
# ---------------------------------------------------------------------------

class LogoRequest(BaseModel):
    url: HttpUrl


class CurrentTenant:
    """
    Representa o tenant obtido do contexto de autenticação.

    Em uma aplicação real, esse objeto deve ser construído a partir
    do JWT/session/API key autenticado, nunca de um tenant_id enviado
    pelo cliente.
    """

    def __init__(self, tenant_id: str):
        self.id= tenant_id


def get_current_tenant()-> CurrentTenant:
    """
    Substituir pela autenticação real da aplicação.

    Exemplo:
        tenant_id = token["tenant_id"]
    """
    raise NotImplementedError


def get_db()-> Session:
    """
    Substituir pela configuração real do SQLAlchemy.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Proteção contra SSRF
# ---------------------------------------------------------------------------

def resolve_public_ips(hostname: str)-> list[ipaddress.IPv4Address| ipaddress.IPv6Address]:
    """
    Resolve o hostname e rejeita endereços IP privados, loopback,
    link-local, multicast, reservados etc.
    """

    try:
        addresses= socket.getaddrinfo(
            hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierroras exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não foi possível resolver o endereço da imagem.",
        ) from exc

    resolved= set()

    for addressin addresses:
        ip= ipaddress.ip_address(address[4][0])

        if not ip.is_global:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="O endereço informado não é permitido.",
            )

        resolved.add(ip)

    if not resolved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O endereço informado não possui um IP válido.",
        )

    return list(resolved)


def validate_image_url(url: str)-> None:
    parsed= urlparse(url)

    if parsed.schemenot in {"http", "https"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A URL deve utilizar HTTP ou HTTPS.",
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL inválida.",
        )

    # Evita URLs com credenciais embutidas:
    # https://usuario:senha@host/...
    if parsed.usernameor parsed.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URLs com credenciais não são permitidas.",
        )

    resolve_public_ips(parsed.hostname)


# ---------------------------------------------------------------------------
# Detecção do formato real da imagem
# ---------------------------------------------------------------------------

def detect_image_format(data: bytes)-> tuple[str, str]:
    """
    Faz uma validação mínima pelo conteúdo (magic bytes), em vez de confiar
    apenas no Content-Type enviado pelo servidor remoto.
    """

    # JPEG
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", ".jpg"

    # PNG
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", ".png"

    # WebP
    if (
        len(data) >= 12
        and data[0:4] == b"RIFF"
        and data[8:12] == b"WEBP"
    ):
        return "image/webp", ".webp"

    raise HTTPException(
        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        detail="O arquivo informado não é uma imagem suportada.",
    )


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

async def download_logo(url: str)-> tuple[bytes, str]:
    validate_image_url(url)

    timeout= httpx.Timeout(
        connect=5.0,
        read=15.0,
        write=5.0,
        pool=5.0,
    )

    limits= httpx.Limits(
        max_connections=10,
        max_keepalive_connections=5,
    )

    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        follow_redirects=False,
    ) as client:

        try:
            response= await client.get(
                url,
                headers={
                    "User-Agent":"MySaaS-LogoFetcher/1.0",
                    "Accept":"image/jpeg,image/png,image/webp",
                },
            )
        except httpx.HTTPErroras exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Não foi possível baixar a imagem.",
            ) from exc

    if response.status_code!= 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O servidor remoto não retornou a imagem.",
        )

    # O servidor remoto pode mentir sobre Content-Length/Content-Type,
    # portanto o tamanho é validado novamente sobre os bytes recebidos.
    data= response.content

    if len(data) > MAX_LOGO_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="A imagem excede o tamanho máximo permitido.",
        )

    detected_content_type, extension= detect_image_format(data)

    # Content-Type remoto pode ser incorreto, mas se estiver presente
    # e for incompatível, rejeitamos a resposta.
    remote_content_type= response.headers.get("content-type","")
    remote_content_type= remote_content_type.split(";",1)[0].lower()

    if (
        remote_content_type
        and remote_content_type!= detected_content_type
        and remote_content_typenot in ALLOWED_CONTENT_TYPES
    ):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="O tipo da imagem não é suportado.",
        )

    return data, extension


# ---------------------------------------------------------------------------
# Persistência
# ---------------------------------------------------------------------------

def save_logo(tenant_id: str, data: bytes, extension: str)-> str:
    """
    O nome do arquivo é derivado do tenant autenticado.

    O tenant_id não vem da requisição enviada pelo usuário.
    """

    tenant_hash= hashlib.sha256(
        tenant_id.encode("utf-8")
    ).hexdigest()

    tenant_directory= LOGO_DIRECTORY/ tenant_hash
    tenant_directory.mkdir(mode=0o750, parents=True, exist_ok=True)

    filename= f"logo{extension}"
    destination= tenant_directory/ filename

    temporary= tenant_directory/ f".logo{extension}.tmp"

    try:
        temporary.write_bytes(data)
        temporary.replace(destination)
    except OSError as exc:
        temporary.unlink(missing_ok=True)

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível armazenar o logotipo.",
        ) from exc

    # Retornamos somente uma referência lógica.
    # O caminho físico não é exposto ao cliente.
    return f"/logos/{tenant_hash}/{filename}"


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

@app.put("/api/v1/account/logo", status_code=status.HTTP_200_OK)
async def update_account_logo(
    payload: LogoRequest,
    tenant: CurrentTenant= Depends(get_current_tenant),
    db: Session= Depends(get_db),
):
    """
    Atualiza o logotipo da empresa atualmente autenticada.

    O tenant é determinado pela sessão/token, portanto o cliente não
    consegue escolher outro tenant simplesmente alterando um ID no JSON.
    """

    data, extension= await download_logo(str(payload.url))

    logo_url= save_logo(
        tenant_id=tenant.id,
        data=data,
        extension=extension,
    )

    # Exemplo de atualização da conta.
    #
    # Substitua "Account" pelo model SQLAlchemy real da aplicação.
    db.execute(
        update(Account)
        .where(Account.id== tenant.id)
        .values(logo_url=logo_url)
    )

    db.commit()

    return {
        "logo_url": logo_url,
    }