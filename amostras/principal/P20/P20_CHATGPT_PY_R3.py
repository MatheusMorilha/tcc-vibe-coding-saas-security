
import os
import secrets
import hashlib
import smtplib

from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from uuid import UUID

from fastapi import FastAPI, Depends, Header, HTTPException
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from sqlalchemy import (
    create_engine,
    String,
    DateTime,
    ForeignKey,
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
from sqlalchemy.dialects.postgresql import UUID as PG_UUID


# --------------------------------------------------
# Configuração
# --------------------------------------------------

DATABASE_URL = os.environ["DATABASE_URL"]
FRONTEND_URL = os.environ["FRONTEND_URL"]

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

password_hasher = PasswordHash.recommended()
app = FastAPI(title="SaaS - Recuperação de senha")


# --------------------------------------------------
# Modelos
# --------------------------------------------------

class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True
    )
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(
        String(320), nullable=False
    )
    password_hash: Mapped[str] = mapped_column(
        String(255), nullable=False
    )


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True
    )
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), nullable=False, index=True
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


# Em produção, use migrações com Alembic em vez de
# criar tabelas automaticamente durante a inicialização.
# Base.metadata.create_all(engine)


def get_db():
    with SessionLocal() as db:
        yield db


# --------------------------------------------------
# Schemas
# --------------------------------------------------

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=40, max_length=200)
    new_password: str = Field(min_length=12, max_length=128)


# --------------------------------------------------
# E-mail
# --------------------------------------------------

def send_reset_email(to_email: str, token: str) -> None:
    # Configure estas variáveis no ambiente do servidor.
    smtp_host = os.environ["SMTP_HOST"]
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.environ["SMTP_USER"]
    smtp_password = os.environ["SMTP_PASSWORD"]
    sender = os.environ["SMTP_FROM"]

    reset_link = f"{FRONTEND_URL}/reset-password?token={token}"

    message = EmailMessage()
    message["Subject"] = "Redefinição de senha"
    message["From"] = sender
    message["To"] = to_email
    message.set_content(
        "Recebemos uma solicitação para redefinir sua senha.\n\n"
        f"Acesse o link para continuar: {reset_link}\n\n"
        "O link expira em 30 minutos e pode ser usado uma única vez. "
        "Se você não solicitou a redefinição, ignore esta mensagem."
    )

    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        smtp.starttls()
        smtp.login(smtp_user, smtp_password)
        smtp.send_message(message)


# --------------------------------------------------
# Rota 1: solicitar recuperação
# --------------------------------------------------

@app.post("/auth/password/forgot")
def forgot_password(
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db),
    x_tenant_id: UUID = Header(alias="X-Tenant-ID"),
):
    # O tenant deve ser resolvido e validado por uma
    # camada confiável de middleware ou gateway.
    user = db.scalar(
        select(User).where(
            User.tenant_id == x_tenant_id,
            User.email == str(payload.email).lower(),
        )
    )

    # Não revela se o e-mail está cadastrado.
    generic_response = {
        "message": (
            "Se os dados corresponderem a uma conta, "
            "você receberá instruções por e-mail."
        )
    }

    if user is None:
        return generic_response

    # Token aleatório: o valor original só é enviado por e-mail.
    raw_token = secrets.token_urlsafe(32)
    token_digest = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    reset_record = PasswordResetToken(
        id=__import__("uuid").uuid4(),
        user_id=user.id,
        tenant_id=user.tenant_id,
        token_hash=token_digest,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        used_at=None,
    )

    db.add(reset_record)
    db.commit()

    try:
        send_reset_email(user.email, raw_token)
    except Exception:
        # Não registra o token nem o link nos logs.
        # Em produção, prefira uma fila de envio/outbox
        # para não perder mensagens após o commit.
        db.delete(reset_record)
        db.commit()
        raise HTTPException(
            status_code=503,
            detail="Não foi possível enviar o e-mail. Tente novamente.",
        )

    return generic_response


# --------------------------------------------------
# Rota 2: redefinir senha
# --------------------------------------------------

@app.post("/auth/password/reset")
def reset_password(
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    token_digest = hashlib.sha256(
        payload.token.encode("utf-8")
    ).hexdigest()

    now = datetime.now(timezone.utc)

    # O bloqueio da linha ajuda a evitar dois usos concorrentes.
    reset_record = db.scalar(
        select(PasswordResetToken)
        .where(PasswordResetToken.token_hash == token_digest)
        .with_for_update()
    )

    if (
        reset_record is None
        or reset_record.used_at is not None
        or reset_record.expires_at <= now
    ):
        raise HTTPException(
            status_code=400,
            detail="Token inválido ou expirado.",
        )

    user = db.scalar(
        select(User).where(
            User.id == reset_record.user_id,
            User.tenant_id == reset_record.tenant_id,
        )
    )

    if user is None:
        raise HTTPException(
            status_code=400,
            detail="Token inválido ou expirado.",
        )

    # Nunca armazenar senha em texto puro.
    user.password_hash = password_hasher.hash(
        payload.new_password
    )
    reset_record.used_at = now

    # Invalida também outros tokens de recuperação do usuário.
    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.tenant_id == user.tenant_id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.id != reset_record.id,
        )
        .values(used_at=now)
    )

    db.commit()

    return {
        "message": "Senha redefinida com sucesso."
    }
