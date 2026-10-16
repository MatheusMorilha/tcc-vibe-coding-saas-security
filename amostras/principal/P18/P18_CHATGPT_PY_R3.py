from datetime import datetime, timedelta, timezone
import secrets
import hashlib

from fastapi import APIRouter, Depends, HTTPException, status

router= APIRouter(prefix="/users", tags=["users"])

CODE_EXPIRATION_MINUTES= 10


# Interfaces simplificadas para ilustrar as dependências.
class CurrentUser:
    def __init__(self, id: str, company_id: str, contact: str):
        self.id= id
        self.company_id= company_id
        self.contact= contact


class UserRepository:
    async def get_by_id(self, user_id: str, company_id: str):
        """
        A consulta DEVE sempre filtrar pelo tenant.
        """
        # SELECT * FROM users
        # WHERE id = :user_id AND company_id = :company_id
        raise NotImplementedError

    async def save_verification_code(
        self,
        user_id: str,
        company_id: str,
        code_hash: str,
        expires_at: datetime,
    ):
        raise NotImplementedError


class MessageSender:
    async def send_verification_code(self, destination: str, code: str):
        raise NotImplementedError


async def get_current_user()-> CurrentUser:
    raise NotImplementedError


user_repository= UserRepository()
message_sender= MessageSender()


def generate_verification_code()-> str:
    """
    Gera um código numérico criptograficamente seguro.
    """
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_code(code: str)-> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


@router.post(
    "/me/contact/verification/resend",
    status_code=status.HTTP_202_ACCEPTED,
)
async def resend_contact_verification(
    current_user: CurrentUser= Depends(get_current_user),
):
    """
    Reenvia o código de verificação do contato cadastrado
    para o usuário autenticado.
    """

    # 1. Busca sempre dentro do tenant do usuário autenticado.
    user= await user_repository.get_by_id(
        user_id=current_user.id,
        company_id=current_user.company_id,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado.",
        )

    if not user.contact:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuário não possui um contato cadastrado.",
        )

    # 2. Gera um novo código.
    code= generate_verification_code()

    # 3. Nunca persiste o código em texto puro.
    code_hash= hash_code(code)

    expires_at= datetime.now(timezone.utc) + timedelta(
        minutes=CODE_EXPIRATION_MINUTES
    )

    # 4. Salva o hash vinculado ao usuário E ao tenant.
    await user_repository.save_verification_code(
        user_id=user.id,
        company_id=current_user.company_id,
        code_hash=code_hash,
        expires_at=expires_at,
    )

    # 5. Envia o código somente para o contato já cadastrado.
    await message_sender.send_verification_code(
        destination=user.contact,
        code=code,
    )

    # Não retorna o código na resposta da API.
    return {
        "message": "Um novo código de verificação foi enviado.",
        "expires_in": CODE_EXPIRATION_MINUTES* 60,
    }