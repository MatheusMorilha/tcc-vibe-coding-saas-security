from datetime import datetime, timedelta, timezone
from secrets import randbelow
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr


router= APIRouter(prefix="/users", tags=["users"])


# ---------------------------------------------------------------------------
# Modelos simplificados
# ---------------------------------------------------------------------------

class AuthenticatedUser:
    def __init__(
        self,
        user_id: str,
        tenant_id: str,
        email: str,
    ):
        self.id= user_id
        self.tenant_id= tenant_id
        self.email= email


class User:
    def __init__(
        self,
        id: str,
        tenant_id: str,
        email: str,
        contact_verified: bool,
    ):
        self.id= id
        self.tenant_id= tenant_id
        self.email= email
        self.contact_verified= contact_verified


class VerificationCode:
    def __init__(
        self,
        user_id: str,
        tenant_id: str,
        code: str,
        expires_at: datetime,
    ):
        self.user_id= user_id
        self.tenant_id= tenant_id
        self.code= code
        self.expires_at= expires_at


# ---------------------------------------------------------------------------
# Dependências / infraestrutura — exemplos
# ---------------------------------------------------------------------------

async def get_authenticated_user()-> AuthenticatedUser:
    """
    Em uma aplicação real, validar aqui o JWT/session e obter o tenant_id
    exclusivamente a partir da identidade autenticada.
    """
    return AuthenticatedUser(
        user_id="user-123",
        tenant_id="tenant-456",
        email="usuario@empresa.com",
    )


async def get_user_by_id_and_tenant(
    user_id: str,
    tenant_id: str,
)-> Optional[User]:
    """
    Consulta deve SEMPRE filtrar pelo tenant_id.

    Exemplo conceitual:
        SELECT *
        FROM users
        WHERE id = :user_id
          AND tenant_id = :tenant_id
        LIMIT 1;
    """
    return User(
        id=user_id,
        tenant_id=tenant_id,
        email="usuario@empresa.com",
        contact_verified=False,
    )


async def invalidate_previous_codes(
    user_id: str,
    tenant_id: str,
)-> None:
    """
    Invalida códigos anteriores do mesmo usuário dentro do mesmo tenant.
    """
    pass


async def save_verification_code(code: VerificationCode)-> None:
    pass


async def send_verification_email(
    recipient: EmailStr,
    code: str,
)-> None:
    """
    Integrar aqui com o provedor de e-mail.
    """
    print(f"Enviando código{code} para{recipient}")


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/me/contact/verification/resend",
    status_code=status.HTTP_202_ACCEPTED,
)
async def resend_contact_verification(
    authenticated_user: AuthenticatedUser= Depends(
        get_authenticated_user
    ),
):
    """
    Gera um novo código de verificação e o envia ao contato cadastrado
    do usuário autenticado.
    """

    user= await get_user_by_id_and_tenant(
        user_id=authenticated_user.id,
        tenant_id=authenticated_user.tenant_id,
    )

    if useris None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado.",
        )

    if user.contact_verified:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="O contato já foi verificado.",
        )

    # Código numérico criptograficamente seguro de 6 dígitos.
    code= f"{randbelow(1_000_000):06d}"

    expires_at= datetime.now(timezone.utc) + timedelta(minutes=10)

    # Garante que códigos anteriores não continuem válidos.
    await invalidate_previous_codes(
        user_id=user.id,
        tenant_id=user.tenant_id,
    )

    verification_code= VerificationCode(
        user_id=user.id,
        tenant_id=user.tenant_id,
        code=code,
        expires_at=expires_at,
    )

    await save_verification_code(verification_code)

    # O destinatário vem do cadastro do usuário, não da requisição.
    await send_verification_email(
        recipient=user.email,
        code=code,
    )

    return {
        "message": "Código de verificação enviado.",
        "expires_in": 600,
    }