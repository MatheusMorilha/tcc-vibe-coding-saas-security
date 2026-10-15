from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

# Ajuste estes imports para a estrutura do seu projeto.
from app.database import get_db
from app.models import User, PasswordResetToken
from app.email import send_email


router= APIRouter(prefix="/auth", tags=["authentication"])

RESET_TOKEN_TTL_MINUTES= 30


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=32)
    new_password: str = Field(min_length=12, max_length=128)


class GenericResponse(BaseModel):
    message: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_email(email: str)-> str:
    return email.strip().lower()


def hash_reset_token(token: str)-> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def utc_now()-> datetime:
    return datetime.now(timezone.utc)


def validate_password(password: str)-> None:
    """
    Regras mínimas de senha.
    Em produção, pode-se adicionar regras de complexidade
    ou utilizar um validador dedicado.
    """
    if len(password) < 12:
        raise ValueError("A senha deve possuir pelo menos 12 caracteres.")

    if password.lower() == passwordor password.upper() == password:
        raise ValueError("A senha deve conter letras maiúsculas e minúsculas.")

    if not any(char.isdigit()for charin password):
        raise ValueError("A senha deve conter pelo menos um número.")


# ---------------------------------------------------------------------------
# POST /auth/forgot-password
# ---------------------------------------------------------------------------

@router.post(
    "/forgot-password",
    response_model=GenericResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    db: AsyncSession= Depends(get_db),
)-> GenericResponse:

    email= normalize_email(payload.email)

    # Não aceitar tenant_id enviado pelo cliente.
    # O usuário é localizado globalmente pelo e-mail.
    result= await db.execute(
        select(User).where(
            User.email== email,
            User.is_active.is_(True),
        )
    )

    user= result.scalar_one_or_none()

    # Resposta idêntica para usuário existente ou inexistente.
    # Isso evita enumeração de contas.
    generic_response= GenericResponse(
        message=(
            "Se existir uma conta associada a este e-mail, "
            "você receberá instruções para redefinir sua senha."
        )
    )

    if useris None:
        return generic_response

    now= utc_now()

    # Invalida tokens anteriores do mesmo usuário.
    await db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id== user.id,
            PasswordResetToken.used_at.is_(None),
        )
        .values(used_at=now)
    )

    # Token criptograficamente seguro.
    raw_token= secrets.token_urlsafe(48)

    token_hash= hash_reset_token(raw_token)

    reset_token= PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=now+ timedelta(minutes=RESET_TOKEN_TTL_MINUTES),
        used_at=None,
    )

    db.add(reset_token)
    await db.commit()

    # O tenant é obtido exclusivamente do registro do usuário.
    # Nunca deve ser aceito um tenant_id vindo do request.
    reset_url= (
        "https://app.example.com/reset-password"
        f"?token={raw_token}"
    )

    await send_email(
        to=user.email,
        subject="Redefinição de senha",
        template="password_reset",
        context={
            "user_name": user.name,
            "reset_url": reset_url,
            "expires_in_minutes": RESET_TOKEN_TTL_MINUTES,
        },
    )

    return generic_response


# ---------------------------------------------------------------------------
# POST /auth/reset-password
# ---------------------------------------------------------------------------

@router.post(
    "/reset-password",
    response_model=GenericResponse,
)
async def reset_password(
    payload: ResetPasswordRequest,
    db: AsyncSession= Depends(get_db),
)-> GenericResponse:

    token_hash= hash_reset_token(payload.token)
    now= utc_now()

    # O token é procurado pelo hash.
    # Não armazenamos o token original no banco.
    result= await db.execute(
        select(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash== token_hash,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at> now,
        )
    )

    reset_token= result.scalar_one_or_none()

    if reset_tokenis None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token inválido ou expirado.",
        )

    # Recuperamos o usuário através do próprio token.
    # O cliente não informa user_id nem tenant_id.
    result= await db.execute(
        select(User).where(
            User.id== reset_token.user_id,
            User.is_active.is_(True),
        )
    )

    user= result.scalar_one_or_none()

    if useris None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token inválido ou expirado.",
        )

    try:
        validate_password(payload.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    # -----------------------------------------------------------------------
    # IMPORTANTE:
    # Nunca armazene senha em texto puro.
    #
    # password_hash deve ser gerado por Argon2id ou bcrypt.
    # Exemplo abaixo usando Argon2.
    # -----------------------------------------------------------------------

    from argon2import PasswordHasher

    password_hasher= PasswordHasher()

    new_password_hash= password_hasher.hash(
        payload.new_password
    )

    # Atualiza a senha do usuário.
    user.password_hash= new_password_hash

    # Marca o token como consumido.
    reset_token.used_at= now

    # Opcionalmente, invalida outros tokens do mesmo usuário.
    await db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id== user.id,
            PasswordResetToken.id!= reset_token.id,
            PasswordResetToken.used_at.is_(None),
        )
        .values(used_at=now)
    )

    await db.commit()

    return GenericResponse(
        message="Senha alterada com sucesso."
    )

from datetimeimport datetime

from sqlalchemyimport (
    DateTime,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.ormimport DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__= "users"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"),
        nullable=False,
        index=True,
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        nullable=False,
        default=True,
    )


class PasswordResetToken(Base):
    __tablename__= "password_reset_tokens"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    # SHA-256 do token, nunca o token original.
    token_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    used_at: Mapped[datetime| None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )