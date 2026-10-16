"""
Cadastro de usuário em plataforma SaaS multilocatária.

Stack: FastAPI, SQLAlchemy 2.x, Pydantic v2, argon2-cffi, PyJWT, slowapi.
Dependências:
    pip install fastapi uvicorn "sqlalchemy>=2" "pydantic[email]>=2" \
                argon2-cffi "pyjwt[crypto]" slowapi psycopg[binary]

Variáveis de ambiente obrigatórias (sem valores padrão, falha ao iniciar):
    DATABASE_URL   ex.: postgresql+psycopg://app:***@db:5432/saas?sslmode=require
    JWT_PUBLIC_KEY chave pública (PEM) usada para validar tokens RS256
    JWT_ISSUER     emissor esperado do token
    JWT_AUDIENCE   audiência esperada do token

Premissas de arquitetura:
  * O token de acesso (emitido pelo serviço de autenticação) carrega
    `sub` (id do usuário) e `tid` (id do tenant).
  * O cadastro é feito por um administrador/owner autenticado, e o novo usuário
    nasce SEMPRE no tenant do administrador.
  * Para auto-cadastro público (signup de nova empresa) o fluxo é outro, pois
    envolve criação de tenant, plano, verificação de e-mail e CAPTCHA.
"""

from __future__ import annotations

import logging
import os
import re
import unicodedata
import uuid
from datetime import datetime

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import HashingError
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    create_engine,
    func,
    select,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)

# --------------------------------------------------------------------------- #
# Configuração (A05 – Security Misconfiguration / A02 – Cryptographic Failures)
# Segredos vêm do ambiente; nunca ficam no código nem têm default inseguro.
# --------------------------------------------------------------------------- #
def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Variável de ambiente obrigatória ausente: {name}")
    return value


DATABASE_URL = _require_env("DATABASE_URL")
JWT_PUBLIC_KEY = _require_env("JWT_PUBLIC_KEY")
JWT_ISSUER = _require_env("JWT_ISSUER")
JWT_AUDIENCE = _require_env("JWT_AUDIENCE")

logger = logging.getLogger("saas.users")  # A09: logs sem dados sensíveis

# --------------------------------------------------------------------------- #
# Persistência
# --------------------------------------------------------------------------- #
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    subscription_status: Mapped[str] = mapped_column(String(20), nullable=False)  # active | suspended | canceled
    max_users: Mapped[int] = mapped_column(Integer, nullable=False)  # limite do plano


class User(Base):
    __tablename__ = "users"
    # Unicidade de e-mail POR tenant, garantida pelo banco (evita race condition).
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("tenants.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="member")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Hash de senha (A02): Argon2id com parâmetros explícitos (OWASP Password Storage)
# --------------------------------------------------------------------------- #
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)

# --------------------------------------------------------------------------- #
# Schemas (A03 – Injection / A04 – Insecure Design / A08 – Mass Assignment)
# --------------------------------------------------------------------------- #
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class UserCreate(BaseModel):
    # extra="forbid": rejeita campos inesperados (tenant_id, role, is_active...),
    # impedindo mass assignment e escalonamento de privilégio via payload.
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=120)
    email: EmailStr = Field(max_length=254)
    # Limite máximo evita DoS por senhas gigantes no Argon2.
    # Sem strip automático: espaços fazem parte da senha. repr=False evita
    # que a senha vaze em repr/logs do objeto.
    password: str = Field(min_length=12, max_length=128, repr=False)

    @field_validator("name", "email", mode="before")
    @classmethod
    def _strip_text_fields(cls, v):
        return v.strip() if isinstance(v, str) else v

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        v = unicodedata.normalize("NFC", v)
        if _CONTROL_CHARS.search(v):
            raise ValueError("Nome contém caracteres inválidos.")
        return v

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return v.lower()

    @model_validator(mode="after")
    def _validate_password_policy(self):
        pwd = self.password
        # Política baseada em NIST SP 800-63B / OWASP ASVS: comprimento > composição.
        if pwd.strip() == "":
            raise ValueError("Senha inválida.")
        if len(set(pwd)) < 5:
            raise ValueError("Senha muito simples.")
        local_part = self.email.split("@", 1)[0]
        lowered = pwd.lower()
        if local_part and len(local_part) >= 4 and local_part in lowered:
            raise ValueError("A senha não deve conter o seu e-mail.")
        if self.name.lower() in lowered:
            raise ValueError("A senha não deve conter o seu nome.")
        # Ponto de extensão: checar a senha contra listas de vazamentos
        # (ex.: HIBP k-anonymity) antes de aceitar.
        return self


class UserOut(BaseModel):
    """Resposta explícita: nunca expõe password_hash nem dados internos (A01/A02)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime


# --------------------------------------------------------------------------- #
# Autenticação e autorização (A01 – Broken Access Control / A07 – Auth Failures)
# --------------------------------------------------------------------------- #
_bearer = HTTPBearer(auto_error=False)
_ADMIN_ROLES = {"owner", "admin"}


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas ou ausentes.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_actor(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if creds is None:
        raise _unauthorized()
    try:
        claims = jwt.decode(
            creds.credentials,
            JWT_PUBLIC_KEY,
            algorithms=["RS256"],  # algoritmo fixo: bloqueia "alg: none" e confusão HS/RS
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iat", "sub", "tid"]},
        )
        user_id = uuid.UUID(claims["sub"])
        tenant_id = uuid.UUID(claims["tid"])
    except (jwt.PyJWTError, ValueError, KeyError, TypeError):
        raise _unauthorized()

    # Não confia cegamente no token: confirma no banco que o ator existe,
    # está ativo e pertence ao tenant declarado.
    actor = db.scalar(
        select(User).where(
            User.id == user_id,
            User.tenant_id == tenant_id,
            User.is_active.is_(True),
        )
    )
    if actor is None:
        raise _unauthorized()
    return actor


def require_tenant_admin(actor: User = Depends(get_current_actor)) -> User:
    if actor.role not in _ADMIN_ROLES:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente.")
    return actor


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
limiter = Limiter(key_func=get_remote_address)  # A04/A07: rate limit contra abuso
router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
def create_user(
    request: Request,  # exigido pelo slowapi
    payload: UserCreate,
    actor: User = Depends(require_tenant_admin),
    db: Session = Depends(get_db),
) -> User:
    # O tenant NUNCA vem do payload: é herdado do ator autenticado (isolamento
    # multilocatário e prevenção de IDOR entre empresas).
    tenant_id = actor.tenant_id

    # Hash fora da seção crítica: operação custosa, não deve segurar lock no banco.
    try:
        password_hash = _hasher.hash(payload.password)
    except HashingError:
        logger.exception("Falha ao gerar hash de senha")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Erro interno.")

    try:
        # Lock na linha do tenant: serializa cadastros concorrentes e impede
        # estourar o limite de usuários do plano por race condition.
        tenant = db.execute(
            select(Tenant).where(Tenant.id == tenant_id).with_for_update()
        ).scalar_one_or_none()

        if tenant is None or tenant.subscription_status != "active":
            raise HTTPException(
                status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa."
            )

        active_users = db.scalar(
            select(func.count())
            .select_from(User)
            .where(User.tenant_id == tenant_id, User.is_active.is_(True))
        )
        if active_users >= tenant.max_users:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Limite de usuários do plano atingido.",
            )

        user = User(
            tenant_id=tenant_id,
            name=payload.name,
            email=payload.email,
            password_hash=password_hash,
            role="member",  # papel definido pelo servidor, nunca pelo cliente
            is_active=True,
        )
        db.add(user)  # ORM com bind parameters: sem SQL concatenado (A03)
        db.commit()
        db.refresh(user)

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Já existe um usuário com este e-mail nesta empresa.",
        )
    except HTTPException:
        db.rollback()
        raise
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Erro de banco ao criar usuário")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Erro interno.")

    # A09: trilha de auditoria sem PII (sem e-mail, sem senha, sem hash).
    logger.info(
        "user_created",
        extra={
            "tenant_id": str(tenant_id),
            "actor_id": str(actor.id),
            "new_user_id": str(user.id),
            "ip": get_remote_address(request),
        },
    )
    return user


# --------------------------------------------------------------------------- #
# Aplicação (A05 – Security Misconfiguration)
# --------------------------------------------------------------------------- #
app = FastAPI(
    title="SaaS API",
    docs_url=None,  # desabilita Swagger/ReDoc em produção
    redoc_url=None,
    openapi_url=None,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.include_router(router)


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    # O handler padrão devolve o campo "input", o que ecoaria a SENHA na resposta
    # (e potencialmente em logs de proxy). Aqui removemos o valor enviado.
    errors = [
        {"campo": ".".join(str(p) for p in e["loc"] if p != "body"), "mensagem": e["msg"]}
        for e in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    # Nunca expõe stack trace ou detalhes internos ao cliente.
    logger.exception("Erro não tratado")
    return JSONResponse(status_code=500, content={"detail": "Erro interno."})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"  # resposta contém dados pessoais
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response