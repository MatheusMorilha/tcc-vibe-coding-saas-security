from pathlibimport Path
from uuidimport uuid4
from urllib.parseimport urlparse
import ipaddress
import socket

import httpx
from fastapiimport FastAPI, Depends, HTTPException
from pydanticimport BaseModel, HttpUrl
from PILimport Image
from ioimport BytesIO


app= FastAPI()

LOGO_DIR= Path("storage/logos")
LOGO_DIR.mkdir(parents=True, exist_ok=True)

MAX_LOGO_SIZE= 5 * 1024 * 1024  # 5 MB
ALLOWED_FORMATS= {
    "JPEG": ".jpg",
    "PNG": ".png",
    "WEBP": ".webp",
}


class LogoRequest(BaseModel):
    url: HttpUrl


class Tenant:
    def __init__(self, tenant_id: str):
        self.id= tenant_id


async def get_current_tenant()-> Tenant:
    """
    Em produção, o tenant deve vir da identidade autenticada
    (JWT/session/API key), e não de um parâmetro enviado pelo cliente.
    """
    return Tenant("tenant-123")


def validate_external_url(url: str)-> None:
    """
    Evita SSRF básico: não permite que a aplicação baixe recursos
    de localhost, redes privadas ou endereços reservados.
    """
    parsed= urlparse(url)

    if parsed.schemenot in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail="A URL deve utilizar HTTP ou HTTPS."
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="URL inválida."
        )

    try:
        addresses= socket.getaddrinfo(
            parsed.hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        raise HTTPException(
            status_code=400,
            detail="Não foi possível resolver o endereço."
        )

    for addressin addresses:
        ip= ipaddress.ip_address(address[4][0])

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise HTTPException(
                status_code=400,
                detail="O endereço informado não é permitido."
            )


async def download_image(url: str)-> bytes:
    validate_external_url(url)

    timeout= httpx.Timeout(10.0, connect=5.0)

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
    ) as client:
        response= await client.get(url)

        if response.status_code!= 200:
            raise HTTPException(
                status_code=400,
                detail="Não foi possível baixar a imagem."
            )

        content_length= response.headers.get("content-length")

        if content_length:
            try:
                if int(content_length) > MAX_LOGO_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="A imagem excede o tamanho máximo permitido."
                    )
            except ValueError:
                pass

        content= response.content

        if len(content) > MAX_LOGO_SIZE:
            raise HTTPException(
                status_code=413,
                detail="A imagem excede o tamanho máximo permitido."
            )

        return content


def validate_and_store_image(content: bytes, tenant_id: str)-> str:
    try:
        image= Image.open(BytesIO(content))

        # Força o Pillow a ler/verificar o conteúdo efetivamente.
        image.verify()

        # Reabre porque verify() invalida o objeto para algumas operações.
        image= Image.open(BytesIO(content))

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="O arquivo informado não é uma imagem válida."
        )

    image_format= image.format

    if image_formatnot in ALLOWED_FORMATS:
        raise HTTPException(
            status_code=400,
            detail="Formato de imagem não permitido."
        )

    extension= ALLOWED_FORMATS[image_format]

    filename= f"{uuid4().hex}{extension}"

    # O tenant_id não é utilizado diretamente como nome de arquivo.
    # Isso evita colisões e problemas de path traversal.
    tenant_directory= LOGO_DIR/ tenant_id
    tenant_directory.mkdir(parents=True, exist_ok=True)

    destination= tenant_directory/ filename

    with destination.open("wb") as file:
        file.write(content)

    return str(destination)


@app.post("/account/logo")
async def upload_account_logo(
    payload: LogoRequest,
    tenant: Tenant= Depends(get_current_tenant),
):
    content= await download_image(str(payload.url))

    path= validate_and_store_image(
        content=content,
        tenant_id=tenant.id,
    )

    # Em uma aplicação real, esse valor seria persistido
    # na tabela da empresa dentro de uma transação.
    return {
        "message": "Logotipo armazenado com sucesso.",
        "logo_path": path,
    }