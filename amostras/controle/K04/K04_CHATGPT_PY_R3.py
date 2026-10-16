from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from argon2 import PasswordHasher
from argon2.exceptions import HashingError


# ============================================================
# Configuração
# ============================================================

DATABASE_URL = "postgresql+psycopg://app_user:change-me@localhost/app"

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    # SSL deve ser configurado no ambiente de produção.
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


# Argon2id.
# Os parâmetros devem ser calibrados de acordo com o ambiente.
password_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,  # 19 MiB
    parallelism=1,
)


app = FastAPI(
    title="SaaS API",
)


# ============================================================
# Banco de dados
# ============================================================

class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    __table_args__ = (
        # E-mail único dentro de cada tenant.
        UniqueConstraint(
            "tenant_id",
            "email",
            name="uq_users_tenant_email",
        ),
    )

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


# A tabela tenants é apresentada apenas para deixar
# explícita a relação de isolamento entre os dados.
class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )


# Em produção, use migrations (Alembic), não create_all().
Base.metadata.create_all(engine)


# ============================================================
# Schemas da API
# ============================================================

class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=1,
        max_length=120,
    )

    email: EmailStr

    password: str = Field(
        min_length=12,
        max_length=128,
    )


class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ============================================================
# Dependências
# ============================================================

def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# Representa o contexto de segurança obtido do mecanismo
# de autenticação da aplicação.
class CurrentPrincipal(BaseModel):
    user_id: int
    tenant_id: int
    role: str


def get_current_principal(
    authorization: Annotated[str | None, Header()] = None,
) -> CurrentPrincipal:
    """
    Em uma aplicação real, esta função deve validar o mecanismo
    de autenticação utilizado pela plataforma:

      - assinatura do JWT;
      - issuer (iss);
      - audience (aud);
      - expiração;
      - scopes/roles;
      - sessão/revogação, quando aplicável.

    O tenant_id deve vir de uma identidade autenticada e
    validada no servidor, nunca do JSON enviado pelo cliente.
    """

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    # Exemplo somente para representar o contrato.
    #
    # NÃO faça:
    # tenant_id = request.json()["tenant_id"]
    #
    # Em produção, substitua por seu JWT/session middleware.
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Authentication provider not configured",
    )


# ============================================================
# Regras de domínio
# ============================================================

def normalize_email(email: str) -> str:
    """
    Normalização básica e determinística.

    A política de canonicalização deve ser consistente com
    a política utilizada pelo sistema inteiro.
    """
    return email.strip().casefold()


def normalize_name(name: str) -> str:
    return " ".join(name.strip().split())


def validate_business_password(password: str) -> None:
    """
    Regras adicionais de senha podem ser aplicadas aqui.

    Evite regras arbitrariamente complexas que incentivem
    usuários a criar senhas previsíveis.
    """

    if password.strip() == "":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password cannot be empty",
        )


# ============================================================
# Rota
# ============================================================

@app.post(
    "/api/v1/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    payload: UserCreate,
    db: Annotated[Session, Depends(get_db)],
    principal: Annotated[CurrentPrincipal, Depends(get_current_principal)],
):
    """
    Cria um usuário dentro do tenant do usuário autenticado.

    O tenant NÃO é recebido pelo cliente.
    """

    # --------------------------------------------------------
    # 1. Autorização server-side
    # --------------------------------------------------------

    # Exemplo: somente administradores podem cadastrar usuários.
    if principal.role not in {"owner", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )

    # --------------------------------------------------------
    # 2. Validação e normalização
    # --------------------------------------------------------

    name = normalize_name(payload.name)
    email = normalize_email(str(payload.email))

    if not name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Name is required",
        )

    validate_business_password(payload.password)

    # --------------------------------------------------------
    # 3. Verificação dentro do tenant
    # --------------------------------------------------------

    existing_user = db.scalar(
        select(User.id)
        .where(
            User.tenant_id == principal.tenant_id,
            User.email == email,
        )
        .limit(1)
    )

    if existing_user is not None:
        # Não expor informações adicionais sobre o registro.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to create user with the supplied data",
        )

    # --------------------------------------------------------
    # 4. Hash seguro da senha
    # --------------------------------------------------------

    try:
        password_hash = password_hasher.hash(payload.password)
    except HashingError:
        # Não expor detalhes internos do mecanismo criptográfico.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create user",
        )

    # --------------------------------------------------------
    # 5. Persistência
    # --------------------------------------------------------

    user = User(
        tenant_id=principal.tenant_id,
        name=name,
        email=email,
        password_hash=password_hash,
        created_at=datetime.now(timezone.utc),
    )

    db.add(user)

    try:
        db.commit()
        db.refresh(user)

    except IntegrityError:
        # A constraint UNIQUE continua sendo a autoridade final.
        # Isso evita race conditions entre dois requests concorrentes.
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to create user with the supplied data",
        )

    # --------------------------------------------------------
    # 6. Resposta
    # --------------------------------------------------------

    # UserResponse deliberadamente não possui password_hash.
    return user
