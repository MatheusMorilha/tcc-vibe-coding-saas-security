from __future__ import annotations

import ipaddress
import socket
import uuid
from contextlib import asynccontextmanager
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, HttpUrl
from PIL import Image
from io import BytesIO


MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5 MB

ALLOWED_IMAGE_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

class LogoRequest(BaseModel):
    url: HttpUrl


class CurrentUser:
    """
    Representa o usuário autenticado.

    Em uma aplicação real, este objeto seria produzido pelo middleware/
    dependency de autenticação.
    """

    def __init__(self, user_id: str, account_id: str):
        self.user_id = user_id
        self.account_id = account_id


# ---------------------------------------------------------------------------
# Autenticação
# ---------------------------------------------------------------------------

async def get_current_user() -> CurrentUser:
    """
    Substitua pela implementação real de autenticação/JWT/session.

    O account_id deve ser obtido do token/sessão autenticada, e não
    fornecido pelo cliente.
    """
    return CurrentUser(
        user_id="authenticated-user-id",
        account_id="authenticated-account-id",
    )


# ---------------------------------------------------------------------------
# Validação contra SSRF
# ---------------------------------------------------------------------------

def is_public_ip(hostname: str) -> bool:
    """
    Resolve o hostname e verifica se todos os endereços encontrados
    são públicos.

    Isso impede acesso direto a:
      - localhost
      - loopback
      - redes privadas
      - link-local
      - multicast
      - etc.
    """

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return False

    if not addresses:
        return False

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

    return True


async def validate_image_url(url: str) -> None:
    parsed = httpx.URL(url)

    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A URL deve utilizar HTTP ou HTTPS.",
        )

    if not parsed.host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL inválida.",
        )

    # Não permitimos URLs contendo usuário/senha.
    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credenciais na URL não são permitidas.",
        )

    if not is_public_ip(parsed.host):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O endereço informado não é permitido.",
        )


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

async def download_image(url: str) -> tuple[bytes, str]:
    """
    Baixa a imagem com limite de tamanho e sem seguir redirects
    automaticamente.

    Redirects são tratados explicitamente para que cada destino possa
    passar novamente pela validação anti-SSRF.
    """

    current_url = url

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=5.0,
            read=10.0,
            write=10.0,
            pool=5.0,
        ),
        follow_redirects=False,
    ) as client:

        for _ in range(3):
            await validate_image_url(current_url)

            try:
                async with client.stream(
                    "GET",
                    current_url,
                    headers={
                        "User-Agent": "SaaS-Logo-Downloader/1.0",
                        "Accept": "image/jpeg,image/png,image/webp",
                    },
                ) as response:

                    if response.status_code in {
                        301,
                        302,
                        303,
                        307,
                        308,
                    }:
                        location = response.headers.get("location")

                        if not location:
                            raise HTTPException(
                                status_code=400,
                                detail="Redirecionamento inválido.",
                            )

                        current_url = str(
                            httpx.URL(current_url).join(location)
                        )
                        continue

                    if response.status_code != 200:
                        raise HTTPException(
                            status_code=400,
                            detail="Não foi possível baixar a imagem.",
                        )

                    content_type = (
                        response.headers
                        .get("content-type", "")
                        .split(";")[0]
                        .strip()
                        .lower()
                    )

                    if content_type not in ALLOWED_IMAGE_TYPES:
                        raise HTTPException(
                            status_code=400,
                            detail="O arquivo não é um tipo de imagem permitido.",
                        )

                    # O Content-Length é apenas uma primeira verificação.
                    # O limite real é aplicado durante a leitura.
                    content_length = response.headers.get("content-length")

                    if content_length:
                        try:
                            if int(content_length) > MAX_IMAGE_SIZE:
                                raise HTTPException(
                                    status_code=413,
                                    detail="A imagem excede o tamanho máximo permitido.",
                                )
                        except ValueError:
                            pass

                    chunks: list[bytes] = []
                    total_size = 0

                    async for chunk in response.aiter_bytes(64 * 1024):
                        total_size += len(chunk)

                        if total_size > MAX_IMAGE_SIZE:
                            raise HTTPException(
                                status_code=413,
                                detail="A imagem excede o tamanho máximo permitido.",
                            )

                        chunks.append(chunk)

                    return b"".join(chunks), content_type

            except httpx.RequestError:
                raise HTTPException(
                    status_code=400,
                    detail="Erro ao acessar a URL da imagem.",
                )

        raise HTTPException(
            status_code=400,
            detail="Quantidade máxima de redirecionamentos excedida.",
        )


# ---------------------------------------------------------------------------
# Validação da imagem
# ---------------------------------------------------------------------------

def validate_image(data: bytes, content_type: str) -> tuple[str, int, int]:
    """
    Não confiamos apenas no Content-Type enviado pelo servidor remoto.

    O Pillow tenta interpretar o conteúdo real do arquivo.
    """

    try:
        image = Image.open(BytesIO(data))

        # Verifica se o arquivo realmente pode ser lido.
        image.verify()

        # Reabre porque verify() invalida o objeto anterior.
        image = Image.open(BytesIO(data))

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="O conteúdo baixado não é uma imagem válida.",
        )

    detected_type = Image.MIME.get(image.format)

    if detected_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Formato de imagem não permitido.",
        )

    # Proteção contra imagens descomprimidas absurdamente grandes.
    if image.width > 4096 or image.height > 4096:
        raise HTTPException(
            status_code=400,
            detail="As dimensões da imagem são muito grandes.",
        )

    extension = ALLOWED_IMAGE_TYPES[detected_type]

    return extension, image.width, image.height


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

class ObjectStorage:
    """
    Abstração do storage.

    Em produção, implemente este método usando, por exemplo, S3,
    Azure Blob Storage ou outro object storage.

    A chave contém explicitamente o account_id para manter isolamento
    lógico entre tenants.
    """

    async def put(
        self,
        *,
        key: str,
        data: bytes,
        content_type: str,
    ) -> None:
        # Exemplo conceitual:
        #
        # await s3_client.put_object(
        #     Bucket="my-saas-assets",
        #     Key=key,
        #     Body=data,
        #     ContentType=content_type,
        # )
        #
        # Implementação omitida.
        pass

    async def delete(self, *, key: str) -> None:
        pass


storage = ObjectStorage()


# ---------------------------------------------------------------------------
# Banco de dados
# ---------------------------------------------------------------------------

class AccountRepository:
    async def set_logo(
        self,
        *,
        account_id: str,
        logo_key: str,
    ) -> None:
        """
        Atualiza o logotipo SOMENTE da conta indicada.

        Em uma implementação real, isso seria algo como:

            UPDATE accounts
            SET logo_key = :logo_key
            WHERE id = :account_id

        O account_id deve vir exclusivamente do contexto autenticado.
        """
        pass

    async def get_logo_key(
        self,
        *,
        account_id: str,
    ) -> str | None:
        pass


accounts = AccountRepository()


# ---------------------------------------------------------------------------
# Aplicação
# ---------------------------------------------------------------------------

app = FastAPI()


@app.put("/api/v1/account/logo")
async def update_account_logo(
    payload: LogoRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """
    Atualiza o logotipo da empresa do usuário autenticado.

    O cliente fornece somente:
        {
            "url": "https://example.com/logo.png"
        }

    A empresa é determinada pelo contexto de autenticação.
    """

    account_id = current_user.account_id

    # 1. Baixar e validar a imagem.
    image_data, content_type = await download_image(str(payload.url))

    # 2. Validar o conteúdo real.
    extension, width, height = validate_image(
        image_data,
        content_type,
    )

    # 3. Criar uma chave imprevisível.
    #
    # Não usamos o nome do arquivo fornecido pela URL.
    logo_key = (
        f"accounts/{account_id}/logo/"
        f"{uuid.uuid4().hex}{extension}"
    )

    # 4. Gravar no object storage.
    await storage.put(
        key=logo_key,
        data=image_data,
        content_type=content_type,
    )

    try:
        # 5. Atualizar somente o tenant autenticado.
        await accounts.set_logo(
            account_id=account_id,
            logo_key=logo_key,
        )

    except Exception:
        # Se o banco falhar depois do upload, removemos o objeto
        # para evitar arquivos órfãos.
        await storage.delete(key=logo_key)
        raise

    return {
        "message": "Logotipo atualizado com sucesso.",
        "logo": {
            "key": logo_key,
            "content_type": content_type,
            "width": width,
            "height": height,
        },
    }
