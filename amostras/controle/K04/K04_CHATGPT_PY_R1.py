from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from sqlalchemy import DateTime, String, UniqueConstraint, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


# ============================================================
# Configuração
# ============================================================

DATABASE_URL = "postgresql+psycopg://app_user:change-me@localhost/app_db"

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=1800,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


# ============================================================
# Banco de dados
# ============================================================

class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "email",
            name="uq_users_tenant_email",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(nullable=False, index=True)

    name: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


# Em produção, utilize Alembic para migrations.
# Base.metadata.create_all(engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ============================================================
# Segurança de senha
# ============================================================

# Argon2id é apropriado para armazenamento de senhas.
password_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    return password_context.hash(password)


# ============================================================
# Schemas
# ============================================================

class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=2,
        max_length=120,
    )

    email: EmailStr

    password: str = Field(
        min_length=12,
        max_length=128,
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = " ".join(value.split())

        if not value:
            raise ValueError("Nome inválido")

        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        # A política real pode ser complementada com verificação
        # contra senhas comprometidas.
        if value.strip() != value:
            raise ValueError("Senha não pode começar ou terminar com espaços")

        return value


class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    created_at: datetime


# ============================================================
# Autenticação/autorização
# ============================================================

security = HTTPBearer(auto_error=True)


class AuthenticatedPrincipal(BaseModel):
    user_id: int
    tenant_id: int
    is_tenant_admin: bool


def get_current_principal(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> AuthenticatedPrincipal:
    """
    Em produção, valide aqui o access token emitido pelo serviço
    de autenticação da aplicação.

    NÃO confie em tenant_id enviado pelo cliente.

    Exemplo conceitual:
        token -> valida assinatura/issuer/audience/expiração
              -> obtém user_id
              -> obtém tenant_id
              -> obtém permissões

    Esta implementação não aceita um token arbitrário.
    """

    token = credentials.credentials

    # Substituir pela validação real do JWT/OIDC/session token.
    principal = validate_access_token(token)

    if not principal:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return principal


def validate_access_token(
    token: str,
) -> AuthenticatedPrincipal | None:
    """
    Placeholder proposital.

    A validação deve ser feita por uma biblioteca de JWT/OIDC
    ou pelo mecanismo oficial de autenticação da aplicação.

    Nunca decodifique simplesmente o JWT e confie no payload.
    """

    raise NotImplementedError(
        "Implementar validação do access token"
    )


def require_tenant_admin(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> AuthenticatedPrincipal:

    if not principal.is_tenant_admin:
        # Não revelar detalhes sobre autorização interna.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operação não permitida",
        )

    return principal


# ============================================================
# Aplicação
# ============================================================

app = FastAPI()


# ============================================================
# Endpoint de cadastro
# ============================================================

@app.post(
    "/api/v1/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    principal: AuthenticatedPrincipal = Depends(require_tenant_admin),
) -> UserResponse:

    # O tenant é obtido do contexto autenticado.
    # O cliente não pode escolher outro tenant.
    tenant_id = principal.tenant_id

    # Normalização consistente para evitar duplicidades como:
    # User@Example.com
    # user@example.com
    normalized_email = str(payload.email).strip().casefold()

    # Consulta parametrizada através do ORM.
    existing_user = db.scalar(
        select(User).where(
            User.tenant_id == tenant_id,
            User.email == normalized_email,
        )
    )

    if existing_user is not None:
        # Não informar detalhes adicionais sobre o registro.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Não foi possível cadastrar o usuário",
        )

    password_hash = hash_password(payload.password)

    user = User(
        tenant_id=tenant_id,
        name=payload.name,
        email=normalized_email,
        password_hash=password_hash,
        created_at=datetime.now(timezone.utc),
    )

    db.add(user)

    try:
        db.commit()
        db.refresh(user)

    except Exception:
        db.rollback()

        # Em produção, registre o erro internamente sem expor
        # stack trace, SQL ou informações sensíveis ao cliente.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Não foi possível cadastrar o usuário",
        )

    # Explicitamente NÃO retornamos:
    # - password
    # - password_hash
    # - tenant_id
    # - tokens
    # - dados internos da aplicação

    return UserResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        created_at=user.created_at,
    )
