
# app.py

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Generator

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    create_engine,
    select,
    update,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)

DATABASE_URL = os.environ["DATABASE_URL"]
RESET_TOKEN_TTL_MINUTES = 30

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(
    bind=engine,
    expire_on_commit=False,
)

app = FastAPI(title="SaaS - Recuperação de senha")
password_hasher = PasswordHasher()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )
    tenant_id: Mapped[int] = mapped_column(
        Integer, nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(
        String(320), nullable=False, index=True
    )
    password_hash: Mapped[str] = mapped_column(
        String(255), nullable=False
    )


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[int] = mapped_column(
        Integer, nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


# Em produção, gerencie o esquema com Alembic.
# Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as db:
        yield db


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=43, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


def send_reset_email(email: str, reset_url: str) -> None:
    """
    Integre aqui um provedor de e-mail transacional.
    Envie reset_url ao destinatário usando HTTPS.
    Não registre o token em logs.
    """
    raise NotImplementedError(
        "Configure o provedor de e-mail transacional."
    )


@app.post(
    "/auth/password/forgot",
    status_code=status.HTTP_202_ACCEPTED,
)
def request_password_reset(
    payload: PasswordResetRequest,
    db: Session = Depends(get_db),
):
    # O mesmo e-mail pode existir em tenants diferentes.
    # Cada conta recebe um token associado ao seu próprio tenant.
    email = str(payload.email).strip().lower()

    users = db.scalars(
        select(User).where(User.email == email)
    ).all()

    # Resposta externa idêntica para e-mails conhecidos e desconhecidos.
    for user in users:
        raw_token = secrets.token_urlsafe(32)

        reset_record = PasswordResetToken(
            user_id=user.id,
            tenant_id=user.tenant_id,
            token_hash=hash_token(raw_token),
            expires_at=utc_now()
            + timedelta(minutes=RESET_TOKEN_TTL_MINUTES),
        )

        db.add(reset_record)

        # O link deve apontar para o frontend HTTPS da aplicação.
        reset_url = (
            f"{os.environ['FRONTEND_URL'].rstrip('/')}"
            f"/reset-password?token={raw_token}"
        )

        # Em produção, prefira uma fila de envio de e-mails.
        # Trate falhas sem expor a existência da conta.
        # A implementação real deve persistir o token antes
        # de disparar o e-mail.
        try:
            db.flush()
            send_reset_email(email, reset_url)
        except Exception:
            # Não deixe um token não enviado ativo.
            db.delete(reset_record)
            continue

    db.commit()

    return {
        "message": (
            "Se o e-mail estiver cadastrado, "
            "você receberá as instruções para redefinir a senha."
        )
    }


@app.post("/auth/password/reset")
def reset_password(
    payload: PasswordResetConfirm,
    db: Session = Depends(get_db),
):
    now = utc_now()
    token_digest = hash_token(payload.token)

    # O token é procurado pelo hash, nunca pelo valor original.
    try:
        with db.begin():
            reset_record = db.scalar(
                select(PasswordResetToken)
                .where(
                    PasswordResetToken.token_hash
                    == token_digest,
                    PasswordResetToken.used_at.is_(None),
                    PasswordResetToken.expires_at > now,
                )
                .with_for_update()
            )

            if reset_record is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Token inválido ou expirado.",
                )

            # Confirma que o usuário pertence ao mesmo tenant
            # associado ao token. O tenant não vem do cliente.
            user = db.scalar(
                select(User).where(
                    User.id == reset_record.user_id,
                    User.tenant_id == reset_record.tenant_id,
                )
            )

            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Token inválido ou expirado.",
                )

            # Valide a senha com a política da aplicação.
            new_hash = password_hasher.hash(
                payload.new_password
            )

            # Consome o token apenas se ainda estiver válido.
            result = db.execute(
                update(PasswordResetToken)
                .where(
                    PasswordResetToken.id == reset_record.id,
                    PasswordResetToken.used_at.is_(None),
                    PasswordResetToken.expires_at > now,
                )
                .values(used_at=now)
            )

            if result.rowcount != 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Token inválido ou expirado.",
                )

            user.password_hash = new_hash

            # Opcional: revogue sessões e refresh tokens
            # do usuário nesta mesma transação, se aplicável.

    except HTTPException:
        raise

    return {
        "message": "Senha redefinida com sucesso."
    }
