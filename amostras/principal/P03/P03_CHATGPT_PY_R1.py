import os
from io import BytesIO
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from PIL import Image, UnidentifiedImageError
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_current_user
from app.models import Company

router = APIRouter(prefix="/companies", tags=["Companies"])

MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_FORMATS = {
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "WEBP": "image/webp",
}

# Domínios confiáveis, configurados no ambiente.
ALLOWED_IMAGE_HOSTS = {
    host.strip().lower()
    for host in os.getenv("ALLOWED_IMAGE_HOSTS", "").split(",")
    if host.strip()
}


class LogoRequest(BaseModel):
    image_url: HttpUrl


@router.put("/me/logo")
async def update_company_logo(
    payload: LogoRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # 1. Obtém a empresa a partir do usuário autenticado.
    company = (
        db.query(Company)
        .filter(Company.id == current_user.company_id)
        .first()
    )

    if company is None:
        raise HTTPException(
            status_code=404,
            detail="Empresa não encontrada.",
        )

    # 2. Valida o endereço antes de realizar a requisição externa.
    url = str(payload.image_url)
    parsed_url = urlparse(url)
    hostname = (parsed_url.hostname or "").lower()

    if (
        parsed_url.scheme != "https"
        or not hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
        or hostname not in ALLOWED_IMAGE_HOSTS
    ):
        raise HTTPException(
            status_code=400,
            detail="URL HTTPS inválida ou domínio não autorizado.",
        )

    # 3. Baixa a imagem com timeout e limite de tamanho.
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,
        ) as client:
            async with client.stream("GET", url) as response:
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=400,
                        detail="Não foi possível baixar a imagem.",
                    )

                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        if int(content_length) > MAX_IMAGE_SIZE:
                            raise HTTPException(
                                status_code=413,
                                detail="A imagem excede o limite de 5 MB.",
                            )
                    except ValueError:
                        raise HTTPException(
                            status_code=400,
                            detail="Tamanho de arquivo inválido.",
                        )

                chunks = []
                total_size = 0

                async for chunk in response.aiter_bytes():
                    total_size += len(chunk)

                    if total_size > MAX_IMAGE_SIZE:
                        raise HTTPException(
                            status_code=413,
                            detail="A imagem excede o limite de 5 MB.",
                        )

                    chunks.append(chunk)

                image_bytes = b"".join(chunks)

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="Tempo limite excedido ao baixar a imagem.",
        )
    except httpx.RequestError:
        raise HTTPException(
            status_code=502,
            detail="Erro ao acessar o endereço da imagem.",
        )

    # 4. Valida o conteúdo real, sem confiar na extensão ou no MIME enviado.
    try:
        with Image.open(BytesIO(image_bytes)) as image:
            image_format = image.format

            if image_format not in ALLOWED_FORMATS:
                raise HTTPException(
                    status_code=415,
                    detail="Formato não permitido. Use JPEG, PNG ou WebP.",
                )

            image.verify()

        # Reabre e normaliza a imagem para remover metadados desnecessários.
        with Image.open(BytesIO(image_bytes)) as image:
            image.load()

            if image.width * image.height > 20_000_000:
                raise HTTPException(
                    status_code=413,
                    detail="A resolução da imagem é muito alta.",
                )

            if image_format == "JPEG":
                image = image.convert("RGB")

            output = BytesIO()
            image.save(output, format=image_format, optimize=True)
            sanitized_bytes = output.getvalue()

    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise HTTPException(
            status_code=400,
            detail="O arquivo recebido não é uma imagem válida.",
        )

    # 5. Atualiza apenas a empresa vinculada ao usuário autenticado.
    company.logo_data = sanitized_bytes
    company.logo_content_type = ALLOWED_FORMATS[image_format]

    db.commit()

    return {
        "message": "Logotipo atualizado com sucesso.",
        "content_type": company.logo_content_type,
        "size_bytes": len(sanitized_bytes),
    }