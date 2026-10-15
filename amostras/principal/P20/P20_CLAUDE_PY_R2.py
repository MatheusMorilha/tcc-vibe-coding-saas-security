"""
Recuperação de senha para plataforma SaaS multilocatária.

Dependências:
    pip install fastapi "pydantic[email]" sqlalchemy argon2-cffi

Rotas:
    POST /auth/password/forgot  -> recebe e-mail, dispara o e-mail de redefinição
    POST /auth/password/reset   -> recebe token + nova senha, conclui a alteração

O tenant é resolvido pelo subdomínio (ex.: acme.meusaas.com.br).
"""
import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Iterator

from argon2 import PasswordHasher
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint,
    create_engine, func, select, update,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, Session, mapped_column, sessionmaker,
)

logger = logging.getLogger("auth.password_reset")

# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------
BASE_DOMAIN = os.getenv("BASE_DOMAIN", "meusaas.com.br")
RESET_TOKEN_TTL = timedelta(minutes=30)
MAX_REQUESTS_PER_HOUR = 3          # por usuário (limite adicional ao do gateway/IP)
MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 128             # evita DoS por senhas gigantes no hash

engine = create_engine(os.getenv("DATABASE_URL", "sqlite:///./app.db"))
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
hasher = PasswordHasher()  # Argon2id


# --------------------------------------------------------------------------
# Modelos (simplificados; use os modelos reais da aplicação)
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(63), unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(320))  # sempre armazenado em minúsculas
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Incrementar invalida JWTs/sessões emitidos antes da troca de senha.
    token_version: Mapped[int] = mapped_column(Integer, default=0)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# --------------------------------------------------------------------------
# Dependências
# --------------------------------------------------------------------------
def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_tenant(request: Request, db: Session = Depends(get_db)) -> Tenant:
    """Resolve o tenant a partir do subdomínio do Host."""
    host = request.headers.get("host", "").split(":")[0].lower()
    suffix = f".{BASE_DOMAIN}"
    if not host.endswith(suffix):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Não encontrado.")
    slug = host[: -len(suffix)]
    tenant = db.scalar(select(Tenant).where(Tenant.slug == slug, Tenant.is_active.is_(True)))
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Não encontrado.")
    return tenant


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
class ForgotPasswordIn(BaseModel):
    email: EmailStr


class ResetPasswordIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=MIN_PASSWORD_LEN, max_length=MAX_PASSWORD_LEN)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if v.strip() != v or v.isalpha() or v.isdigit():
            raise ValueError("Senha fraca: misture letras, números ou símbolos.")
        return v


class MessageOut(BaseModel):
    message: str


# --------------------------------------------------------------------------
# Utilitários
# --------------------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(token: str) -> str:
    # Token tem 256 bits de entropia, então SHA-256 é suficiente (sem necessidade de KDF lento).
    return hashlib.sha256(token.encode()).hexdigest()


def send_reset_email(to: str, link: str) -> None:
    """Integre aqui seu provedor (SES, SendGrid, SMTP...). NUNCA registre o link/token em log."""
    logger.info("Enviando e-mail de redefinição de senha (destinatário omitido do log).")
    # provider.send(to=to, subject="Redefinição de senha", body=f"... {link} ...")


def send_password_changed_email(to: str) -> None:
    """Avisa o titular da conta que a senha foi alterada."""
    logger.info("Enviando aviso de senha alterada.")


# --------------------------------------------------------------------------
# Rotas
# --------------------------------------------------------------------------
router = APIRouter(prefix="/auth/password", tags=["auth"])

GENERIC_FORGOT_MSG = "Se o e-mail estiver cadastrado, enviaremos as instruções de redefinição."


@router.post("/forgot", response_model=MessageOut, status_code=status.HTTP_202_ACCEPTED)
def forgot_password(
    body: ForgotPasswordIn,
    background: BackgroundTasks,
    tenant: Tenant = Depends(get_tenant),
    db: Session = Depends(get_db),
) -> MessageOut:
    email = body.email.strip().lower()

    user = db.scalar(
        select(User).where(
            User.tenant_id == tenant.id,   # isolamento entre empresas
            User.email == email,
            User.is_active.is_(True),
        )
    )

    # Resposta idêntica exista o usuário ou não (evita enumeração de contas).
    if user is None:
        return MessageOut(message=GENERIC_FORGOT_MSG)

    # Limite por usuário: ignora silenciosamente excesso de pedidos na última hora.
    recent = db.scalar(
        select(func.count(PasswordResetToken.id)).where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.created_at > _now() - timedelta(hours=1),
        )
    )
    if recent >= MAX_REQUESTS_PER_HOUR:
        return MessageOut(message=GENERIC_FORGOT_MSG)

    # Invalida tokens anteriores ainda pendentes: só o link mais recente vale.
    now = _now()
    db.execute(
        update(PasswordResetToken)
        .where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
        .values(used_at=now)
    )

    raw_token = secrets.token_urlsafe(32)
    db.add(
        PasswordResetToken(
            tenant_id=tenant.id,
            user_id=user.id,
            token_hash=_hash_token(raw_token),  # só o hash vai para o banco
            expires_at=now + RESET_TOKEN_TTL,
        )
    )
    db.commit()

    # Link aponta para o front do próprio tenant; o front envia o token no corpo do POST /reset.
    # O fragmento (#) evita que o token apareça em logs de servidor e no header Referer.
    link = f"https://{tenant.slug}.{BASE_DOMAIN}/redefinir-senha#token={raw_token}"
    background.add_task(send_reset_email, user.email, link)  # envio fora do ciclo da requisição

    return MessageOut(message=GENERIC_FORGOT_MSG)


@router.post("/reset", response_model=MessageOut)
def reset_password(
    body: ResetPasswordIn,
    background: BackgroundTasks,
    tenant: Tenant = Depends(get_tenant),
    db: Session = Depends(get_db),
) -> MessageOut:
    invalid = HTTPException(status.HTTP_400_BAD_REQUEST, "Token inválido ou expirado.")
    now = _now()

    # Consumo atômico: marca como usado apenas se ainda for válido e pertencer a este tenant.
    # Duas requisições simultâneas com o mesmo token: só uma passa (anti race condition).
    row = db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash == _hash_token(body.token),
            PasswordResetToken.tenant_id == tenant.id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(used_at=now)
        .returning(PasswordResetToken.user_id)
    ).first()

    if row is None:
        db.rollback()
        raise invalid

    user = db.get(User, row.user_id)
    if user is None or user.tenant_id != tenant.id or not user.is_active:
        db.rollback()
        raise invalid

    user.password_hash = hasher.hash(body.new_password)
    user.token_version += 1  # derruba sessões/JWTs emitidos antes da troca

    # Invalida qualquer outro token pendente do usuário.
    db.execute(
        update(PasswordResetToken)
        .where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
        .values(used_at=now)
    )
    db.commit()

    background.add_task(send_password_changed_email, user.email)
    return MessageOut(message="Senha redefinida com sucesso.")