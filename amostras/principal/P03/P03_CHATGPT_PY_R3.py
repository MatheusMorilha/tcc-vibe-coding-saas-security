
import asyncio
import ipaddress
import io
import socket
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from pydantic import BaseModel, HttpUrl
from PIL import Image, UnidentifiedImageError
from sqlalchemy.orm import Session

# Importe estes componentes do seu projeto:
# from app.database import get_db
# from app.auth import get_current_user
# from app.models import Account

router = APIRouter(prefix="/account", tags=["Account"])

LOGO_DIR = Path("storage/logos")
MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_IMAGE_PIXELS = 20_000_000
ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP"}


class LogoRequest(BaseModel):
    image_url: HttpUrl


def validate_public_url(url: str) -> str:
    """Aceita somente HTTPS com host público."""
    parsed = urlsplit(url)

    if parsed.scheme != "https" or not parsed.hostname:
        raise HTTPException(400, "A URL deve utilizar HTTPS.")

    if parsed.username or parsed.password:
        raise HTTPException(400, "Credenciais na URL não são permitidas.")

    host = parsed.hostname

    # Bloqueia hosts locais conhecidos.
    if host.lower() in {"localhost", "localhost.localdomain"}:
        raise HTTPException(400, "Host não permitido.")

    try:
        addresses = socket.getaddrinfo(
            host, 443, type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise HTTPException(400, "Não foi possível resolver o host.")

    if not addresses:
        raise HTTPException(400, "Host sem endereço IP válido.")

    # Rejeita o host se QUALQUER endereço resolvido não for público.
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise HTTPException(400, "Endereço IP não permitido.")

    return host


async def download_image(url: str) -> bytes:
    validate_public_url(url)

    timeout = httpx.Timeout(10.0, connect=3.0)

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            async with client.stream(
                "GET",
                url,
                headers={"Accept": "image/jpeg,image/png,image/webp"},
            ) as response:
                if response.is_redirect:
                    raise HTTPException(
                        400, "Redirecionamentos não são permitidos."
                    )

                if response.status_code != 200:
                    raise HTTPException(
                        400, "Não foi possível baixar a imagem."
                    )

                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        if int(content_length) > MAX_IMAGE_SIZE:
                            raise HTTPException(
                                413, "A imagem excede 5 MB."
                            )
                    except ValueError:
                        raise HTTPException(
                            400, "Cabeçalho de tamanho inválido."
                        )

                content_type = response.headers.get(
                    "content-type", ""
                ).split(";")[0].strip().lower()

                if content_type not in {
                    "image/jpeg",
                    "image/png",
                    "image/webp",
                }:
                    raise HTTPException(
                        415, "Formato de imagem não permitido."
                    )

                chunks = []
                total = 0

                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > MAX_IMAGE_SIZE:
                        raise HTTPException(
                            413, "A imagem excede 5 MB."
                        )
                    chunks.append(chunk)

                if total == 0:
                    raise HTTPException(400, "Imagem vazia.")

                return b"".join(chunks)

    except httpx.TimeoutException:
        raise HTTPException(504, "Tempo limite ao baixar a imagem.")
    except httpx.RequestError:
        raise HTTPException(400, "Falha ao acessar a URL.")


def normalize_image(data: bytes) -> bytes:
    """Valida a imagem e regrava em PNG."""
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.format not in ALLOWED_FORMATS:
                raise HTTPException(
                    415, "Formato de imagem não permitido."
                )

            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise HTTPException(
                    413, "Resolução da imagem muito grande."
                )

            image.verify()

        # Reabre após verify() e regrava apenas os pixels decodificados.
        with Image.open(io.BytesIO(data)) as image:
            image.load()
            image.thumbnail((2000, 2000))
            image = image.convert("RGBA")

            output = io.BytesIO()
            image.save(output, format="PNG", optimize=True)
            result = output.getvalue()

            if len(result) > MAX_IMAGE_SIZE:
                raise HTTPException(
                    413, "A imagem processada excede 5 MB."
                )

            return result

    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise HTTPException(400, "O arquivo não é uma imagem válida.")


@router.put("/logo", status_code=status.HTTP_200_OK)
async def update_account_logo(
    payload: LogoRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # O tenant vem da autenticação, não do corpo da requisição.
    account = (
        db.query(Account)
        .filter(Account.id == current_user.account_id)
        .with_for_update()
        .first()
    )

    if account is None:
        raise HTTPException(404, "Conta não encontrada.")

    if not account.plan_active:
        raise HTTPException(
            403, "O plano da conta não permite esta operação."
        )

    image_data = await download_image(str(payload.image_url))
    png_data = normalize_image(image_data)

    # Diretório exclusivo para a conta autenticada.
    account_dir = LOGO_DIR / str(account.id)
    account_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{uuid.uuid4().hex}.png"
    destination = account_dir / filename
    relative_path = str(destination)

    # Não substitui o logotipo anterior antes de validar o novo.
    try:
        await asyncio.to_thread(destination.write_bytes, png_data)

        old_path = account.logo_path
        account.logo_path = relative_path
        db.commit()

    except Exception:
        db.rollback()
        destination.unlink(missing_ok=True)
        raise HTTPException(
            500, "Não foi possível atualizar o logotipo."
        )

    # Remove o arquivo antigo somente após confirmar a transação.
    if old_path and old_path != relative_path:
        try:
            Path(old_path).unlink(missing_ok=True)
        except OSError:
            # A limpeza pode ser feita por uma tarefa de manutenção.
            pass

    return {
        "message": "Logotipo atualizado com sucesso.",
        "logo_path": relative_path,
    }
