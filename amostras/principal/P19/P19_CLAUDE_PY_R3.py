"""
Rota de autenticação para plataforma SaaS multilocatária.

Dependências:
    pip install fastapi uvicorn sqlalchemy argon2-cffi pyjwt "pydantic[email]"

Variáveis de ambiente:
    JWT_SECRET   (obrigatória, >= 32 bytes aleatórios)
    DATABASE_URL (ex.: postgresql+psycopg://user:pass@host/db)
"""
import os
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------
JWT_SECRET = os.environ["JWT_SECRET"]  # falha na inicialização se ausente
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL = timedelta(minutes=30)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

engine = create_engine(os.environ.get("DATABASE_URL", "sqlite:///./app.db"), pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

ph = PasswordHasher()  # Argon2id com parâmetros padrão seguros
# Hash fictício: usado para gastar o mesmo tempo quando o e-mail não existe,
# evitando enumeração de usuários por diferença de tempo de resposta.
_DUMMY_HASH = ph.hash("senha-fictícia-para-equalizar-tempo")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Modelos
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    # active | trial | past_due | canceled
    subscription_status: Mapped[str] = mapped_column(String(20), default="trial")
    subscription_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    users: Mapped[list["User"]] = relationship(back_populates="tenant")

    def has_active_subscription(self) -> bool:
        if self.subscription_status not in ("active", "trial"):
            return False
        if self.subscription_expires_at and self.subscription_expires_at < utcnow():
            return False
        return True


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    # E-mail único globalmente nesta implementação (ver observações).
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="users")


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)  # limita custo de hashing


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # segundos


# --------------------------------------------------------------------------
# Infraestrutura
# --------------------------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(user: User) -> tuple[str, int]:
    now = utcnow()
    payload = {
        "sub": str(user.id),
        "tid": user.tenant_id,  # tenant vai no token; use-o para filtrar TODAS as queries
        "iat": int(now.timestamp()),
        "exp": int((now + ACCESS_TOKEN_TTL).timestamp()),
        "jti": uuid.uuid4().hex,  # permite revogação por lista de bloqueio
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, int(ACCESS_TOKEN_TTL.total_seconds())


INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="E-mail ou senha inválidos.",
    headers={"WWW-Authenticate": "Bearer"},
)


# --------------------------------------------------------------------------
# Rota
# --------------------------------------------------------------------------
app = FastAPI(title="SaaS API")


@app.post("/auth/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    email = body.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))

    # 1) E-mail inexistente: verifica contra hash fictício e responde igual a senha errada.
    if user is None:
        try:
            ph.verify(_DUMMY_HASH, body.password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            pass
        raise INVALID_CREDENTIALS

    # 2) Conta temporariamente bloqueada por tentativas excessivas.
    if user.locked_until and user.locked_until > utcnow():
        retry_after = int((user.locked_until - utcnow()).total_seconds()) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas. Tente novamente mais tarde.",
            headers={"Retry-After": str(retry_after)},
        )

    # 3) Verificação da senha.
    try:
        ph.verify(user.password_hash, body.password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = utcnow() + LOCKOUT_DURATION
            user.failed_attempts = 0
        db.commit()
        raise INVALID_CREDENTIALS

    # 4) Credenciais corretas: só agora revelamos problemas de conta/assinatura.
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Usuário desativado.")

    if not user.tenant.has_active_subscription():
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            detail="A assinatura da empresa não está ativa.",
        )

    # 5) Sucesso: zera contadores, atualiza hash se parâmetros mudaram e emite token.
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(body.password)
    db.commit()

    token, expires_in = create_access_token(user)
    return TokenResponse(access_token=token, expires_in=expires_in)


if __name__ == "__main__":
    Base.metadata.create_all(engine)
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)