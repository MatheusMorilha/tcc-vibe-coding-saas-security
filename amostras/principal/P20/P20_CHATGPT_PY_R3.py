from datetimeimport datetime, timedelta, timezone
from hashlibimport sha256
from secretsimport token_urlsafe

from fastapiimport APIRouter, Depends, HTTPException, status
from pydanticimport BaseModel, EmailStr, Field
from passlib.contextimport CryptContext
from sqlalchemyimport select
from sqlalchemy.ormimport Session

from app.databaseimport get_db
from app.modelsimport User, PasswordResetToken
from app.mailerimport send_password_reset_email


router= APIRouter(prefix="/auth", tags=["authentication"])

pwd_context= CryptContext(schemes=["bcrypt"], deprecated="auto")

RESET_TOKEN_EXPIRATION_MINUTES= 30


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=32)
    new_password: str = Field(min_length=12, max_length=128)


class PasswordResetResponse(BaseModel):
    message: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def hash_token(token: str)-> str:
    return sha256(token.encode("utf-8")).hexdigest()


def validate_password(password: str)-> None:
    if len(password) < 12:
        raise ValueError("A senha deve possuir pelo menos 12 caracteres.")

    if password.isalpha() or password.isdigit():
        raise ValueError(
            "A senha deve conter letras e números ou caracteres especiais."
        )


# ---------------------------------------------------------------------------
# 1. Solicitar recuperação de senha
# ---------------------------------------------------------------------------

@router.post(
    "/password/forgot",
    response_model=PasswordResetResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def request_password_reset(
    payload: PasswordResetRequest,
    db: Session= Depends(get_db),
):
    """
    Solicita o envio de um link de redefinição.

    Importante:
    A resposta é sempre a mesma, mesmo quando o e-mail não existe.
    Isso evita que a API seja utilizada para descobrir usuários cadastrados.
    """

    user= db.scalar(
        select(User).where(
            User.email== payload.email,
            User.is_active.is_(True),
        )
    )

    if useris not None:
        # Invalida tokens anteriores do mesmo usuário.
        previous_tokens= db.scalars(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id== user.id,
                PasswordResetToken.used_at.is_(None),
            )
        ).all()

        for reset_tokenin previous_tokens:
            reset_token.used_at= datetime.now(timezone.utc)

        # Token aleatório, não previsível.
        raw_token= token_urlsafe(48)

        reset_token= PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            expires_at=(
                datetime.now(timezone.utc)
                + timedelta(minutes=RESET_TOKEN_EXPIRATION_MINUTES)
            ),
        )

        db.add(reset_token)
        db.commit()

        reset_url= (
            "https://app.exemplo.com/reset-password"
            f"?token={raw_token}"
        )

        send_password_reset_email(
            recipient=user.email,
            reset_url=reset_url,
        )

    # Não revela se o usuário existe ou não.
    return PasswordResetResponse(
        message=(
            "Se o e-mail estiver cadastrado, "
            "você receberá instruções para redefinir sua senha."
        )
    )


# ---------------------------------------------------------------------------
# 2. Confirmar nova senha
# ---------------------------------------------------------------------------

@router.post(
    "/password/reset",
    response_model=PasswordResetResponse,
)
def reset_password(
    payload: PasswordResetConfirm,
    db: Session= Depends(get_db),
):
    """
    Valida o token e altera a senha.

    O token:
    - é armazenado somente como hash;
    - possui validade limitada;
    - pode ser utilizado apenas uma vez.
    """

    try:
        validate_password(payload.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    token_hash= hash_token(payload.token)

    reset_token= db.scalar(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash== token_hash,
            PasswordResetToken.used_at.is_(None),
        )
    )

    if reset_tokenis None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token de redefinição inválido ou expirado.",
        )

    now= datetime.now(timezone.utc)

    if reset_token.expires_at<= now:
        reset_token.used_at= now
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token de redefinição inválido ou expirado.",
        )

    user= db.scalar(
        select(User).where(
            User.id== reset_token.user_id,
            User.is_active.is_(True),
        )
    )

    if useris None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token de redefinição inválido ou expirado.",
        )

    # O tenant é obtido pelo próprio usuário.
    # Nunca deve ser recebido pelo cliente como parâmetro de confiança.
    user.password_hash= pwd_context.hash(payload.new_password)

    # Token de recuperação é descartável.
    reset_token.used_at= now

    # Opcionalmente, invalide sessões/tokens existentes do usuário.
    # user.token_version += 1

    db.commit()

    return PasswordResetResponse(
        message="Senha redefinida com sucesso."
    )

from datetimeimport datetime

from sqlalchemyimport DateTime, ForeignKey, String
from sqlalchemy.ormimport Mapped, mapped_column, relationship

from app.databaseimport Base


class User(Base):
    __tablename__= "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(index=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(default=True)

    reset_tokens= relationship(
        "PasswordResetToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )


class PasswordResetToken(Base):
    __tablename__= "password_reset_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        index=True,
    )

    # Nunca armazenar o token em texto puro.
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
    )

    used_at: Mapped[datetime| None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    user= relationship(
        "User",
        back_populates="reset_tokens",
    )