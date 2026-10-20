
import hashlib
import os
import secrets
import smtplib

from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Generator

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    create_engine,
    select,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)


# --------------------------------------------------
# Configuração
# --------------------------------------------------

DATABASE_URL = os.environ["DATABASE_URL"]
FRONTEND_URL = os.environ["FRONTEND_URL"]
SMTP_HOST = os.environ["SMTP_HOST"]
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]
EMAIL_FROM = os.environ["EMAIL_FROM"]

TOKEN_TTL_MINUTES = 30

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(
    bind=engine,
    expire_on_commit=False,
)

app = FastAPI(title="SaaS - Recuperação de Senha")
password_hasher = PasswordHash.recommended()


# --------------------------------------------------
# Modelos de persistência
# --------------------------------------------------

class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )
    name: Mapped[str] = mapped_column(String(150))


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(
        String(254), unique=True, nullable=False, index=True
    )
    password_hash: Mapped[str] = mapped_column(
        String(512), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False, index=True
    )
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


# Em produção, aplique migrações com Alembic.
# Não use create_all como substituto das migrações.
# Base.metadata.create_all(engine)


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as db:
        yield db


# --------------------------------------------------
# Schemas da API
# --------------------------------------------------

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=43, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


# --------------------------------------------------
# Utilitários
# --------------------------------------------------

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def send_reset_email(email: str, token: str) -> None:
    # O token bruto existe apenas para compor o link enviado.
    # Nunca o registre em logs.
    reset_url = f"{FRONTEND_URL}/reset-password?token={token}"

    message = EmailMessage()
    message["Subject"] = "Redefinição de senha"
    message["From"] = EMAIL_FROM
    message["To"] = email
    message.set_content(
        "Recebemos uma solicitação de redefinição de senha.\n\n"
        f"Para criar uma nova senha, acesse: {reset_url}\n\n"
        f"O link expira em {TOKEN_TTL_MINUTES} minutos. "
        "Se você não solicitou a redefinição, ignore esta mensagem."
    )

    with smtplib.SMTP_SSL(
        SMTP_HOST, SMTP_PORT, timeout=10
    ) as smtp:
        smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(message)


# --------------------------------------------------
# Rota 1: solicitar redefinição
# --------------------------------------------------

@app.post("/auth/password/forgot", status_code=202)
def forgot_password(
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    # Resposta genérica para evitar enumeração de contas.
    response = {
        "message": (
            "Se o e-mail estiver cadastrado, "
            "você receberá instruções para redefinir a senha."
        )
    }

    email = str(payload.email).strip().lower()

    user = db.scalar(
        select(User).where(
            User.email == email,
            User.is_active.is_(True),
        )
    )

    if user is None:
        return response

    # Token aleatório com 256 bits de entropia.
    raw_token = secrets.token_urlsafe(32)
    token_digest = hash_token(raw_token)

    now = datetime.now(timezone.utc)

    reset_record = PasswordResetToken(
        user_id=user.id,
        tenant_id=user.tenant_id,
        token_hash=token_digest,
        expires_at=now + timedelta(
            minutes=TOKEN_TTL_MINUTES
        ),
    )

    try:
        # Persiste antes de enviar o e-mail.
        db.add(reset_record)
        db.commit()

        send_reset_email(user.email, raw_token)

    except Exception:
        db.rollback()

        # Em produção, registre apenas o erro operacional,
        # sem token, senha ou outros segredos.
        # Prefira uma fila de e-mail/outbox para garantir
        # entrega confiável sem bloquear a requisição.
        raise HTTPException(
            status_code=503,
            detail="Não foi possível processar a solicitação.",
        )

    return response


# --------------------------------------------------
# Rota 2: redefinir senha
# --------------------------------------------------

@app.post("/auth/password/reset")
def reset_password(
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    token_digest = hash_token(payload.token)

    # O bloqueio reduz a possibilidade de dois pedidos
    # consumirem simultaneamente o mesmo token.
    record = db.scalar(
        select(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash == token_digest,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .with_for_update()
    )

    if record is None:
        raise HTTPException(
            status_code=400,
            detail="Token inválido ou expirado.",
        )

    # A associação ao tenant é verificada novamente.
    user = db.scalar(
        select(User).where(
            User.id == record.user_id,
            User.tenant_id == record.tenant_id,
            User.is_active.is_(True),
        )
    )

    if user is None:
        raise HTTPException(
            status_code=400,
            detail="Token inválido ou expirado.",
        )

    # Armazena apenas o hash da nova senha.
    new_hash = password_hasher.hash(payload.new_password)

    try:
        user.password_hash = new_hash
        record.used_at = now

        # Invalida outros tokens pendentes do mesmo usuário
        # e tenant, evitando redefinições antigas posteriores.
        other_tokens = db.scalars(
            select(PasswordResetToken)
            .where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.tenant_id == user.tenant_id,
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.id != record.id,
            )
        ).all()

        for other in other_tokens:
            other.used_at = now

        db.commit()

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Não foi possível redefinir a senha.",
        )

    return {
        "message": "Senha redefinida com sucesso."
    }
