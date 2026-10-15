from datetime import datetime, timedelta, timezone
import hashlib
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr

router= APIRouter(prefix="/v1/auth", tags=["verification"])


# ---------------------------------------------------------------------------
# Dependências / modelos simplificados
# ---------------------------------------------------------------------------

class CurrentUser:
    def __init__(self, user_id: str, tenant_id: str):
        self.id= user_id
        self.tenant_id= tenant_id


class User:
    def __init__(self, id: str, tenant_id: str, email: str, phone: str | None):
        self.id= id
        self.tenant_id= tenant_id
        self.email= email
        self.phone= phone


class VerificationCode:
    def __init__(
        self,
        user_id: str,
        tenant_id: str,
        destination: str,
        code_hash: str,
        expires_at: datetime,
    ):
        self.user_id= user_id
        self.tenant_id= tenant_id
        self.destination= destination
        self.code_hash= code_hash
        self.expires_at= expires_at


class ResendVerificationRequest(BaseModel):
    channel: str = "email"


class ResendVerificationResponse(BaseModel):
    message: str
    expires_in: int


# ---------------------------------------------------------------------------
# Interfaces de infraestrutura
# ---------------------------------------------------------------------------

async def get_current_user()-> CurrentUser:
    """
    Em uma aplicação real, valide aqui o JWT/session e obtenha o tenant_id
    a partir das claims autenticadas.
    """
    raise NotImplementedError


async def get_user_by_id(
    user_id: str,
    tenant_id: str,
)-> User| None:
    """
    IMPORTANTE: a consulta deve sempre filtrar pelo tenant_id.
    """
    raise NotImplementedError


async def save_verification_code(code: VerificationCode)-> None:
    """
    Persistência transacional.
    """
    raise NotImplementedError


async def send_verification_email(
    recipient: EmailStr,
    code: str,
)-> None:
    """
    Integração com o provedor de e-mail.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------

CODE_TTL_SECONDS= 10 * 60
CODE_LENGTH= 6


def generate_verification_code()-> str:
    """
    secrets é apropriado para geração de tokens/códigos de autenticação.
    """
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_verification_code(code: str)-> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

@router.post(
    "/users/me/verification-code/resend",
    response_model=ResendVerificationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def resend_verification_code(
    request: ResendVerificationRequest,
    current_user: CurrentUser= Depends(get_current_user),
):
    """
    Reenvia um novo código para o contato cadastrado do usuário autenticado.
    """

    if request.channel!= "email":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Canal de verificação não suportado.",
        )

    # O tenant_id vem do contexto autenticado e participa da consulta.
    # Isso impede acesso cruzado entre empresas.
    user= await get_user_by_id(
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
    )

    if useris None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado.",
        )

    if not user.email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Usuário não possui e-mail cadastrado.",
        )

    code= generate_verification_code()
    code_hash= hash_verification_code(code)

    expires_at= datetime.now(timezone.utc) + timedelta(
        seconds=CODE_TTL_SECONDS
    )

    verification= VerificationCode(
        user_id=user.id,
        tenant_id=user.tenant_id,
        destination=user.email,
        code_hash=code_hash,
        expires_at=expires_at,
    )

    # Persistir somente o hash do código.
    await save_verification_code(verification)

    # O código em texto puro só existe durante o processo de envio.
    await send_verification_email(
        recipient=user.email,
        code=code,
    )

    return ResendVerificationResponse(
        message="Código de verificação enviado.",
        expires_in=CODE_TTL_SECONDS,
    )