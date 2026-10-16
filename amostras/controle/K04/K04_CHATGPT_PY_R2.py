from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from argon2.exceptions import HashingError
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import DateTime, String, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


app = FastAPI()


# ---------------------------------------------------------------------------
# Configuração de hashing
# ---------------------------------------------------------------------------

# Argon2id é recomendado pela OWASP para armazenamento de senhas.
# Os parâmetros abaixo correspondem ao mínimo recomendado pela OWASP:
# memory_cost = 19 MiB
# time_cost   = 2
# parallelism = 1
password_hasher = PasswordHasher(
    memory_cost=19_456,
    time_cost=2,
    parallelism=1,
)


# ---------------------------------------------------------------------------
# Banco
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    __table_args__ = (
        # E-mail é único DENTRO do tenant.
        UniqueConstraint(
            "tenant_id",
            "email",
            name="uq_users_tenant_email",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=uuid4,
    )

    tenant_id: Mapped[UUID] = mapped_column(
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

    # Nunca retornar este campo pela API.
    password_hash: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Schemas de entrada/saída
# ---------------------------------------------------------------------------

class UserCreateRequest(BaseModel):
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
    id: UUID
    name: str
    email: EmailStr
    created_at: datetime


# ---------------------------------------------------------------------------
# Contexto de autenticação
# ---------------------------------------------------------------------------

class CurrentUser(BaseModel):
    id: UUID
    tenant_id: UUID
    role: str


def get_current_user() -> CurrentUser:
    """
    Exemplo simplificado.

    Em produção, esta função deve validar a sessão/token do usuário
    e obter tenant_id e role a partir de dados confiáveis do servidor.

    NÃO aceite tenant_id diretamente do JSON enviado pelo cliente.
    """

    # Exemplo apenas para demonstrar a interface:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Autenticação necessária",
    )


def require_tenant_admin(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """
    Apenas administradores do tenant podem cadastrar usuários.
    """

    if current_user.role != "tenant_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operação não permitida",
        )

    return current_user


# ---------------------------------------------------------------------------
# Dependência de banco
# ---------------------------------------------------------------------------

def get_db() -> Session:
    """
    Substitua pela sua SessionFactory/engine de produção.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    payload: UserCreateRequest,
    current_user: CurrentUser = Depends(require_tenant_admin),
    db: Session = Depends(get_db),
) -> UserResponse:

    # ---------------------------------------------------------------
    # 1. Normalização controlada
    # ---------------------------------------------------------------

    name = payload.name.strip()
    email = payload.email.strip().lower()

    if not name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Nome inválido",
        )

    # ---------------------------------------------------------------
    # 2. Verificação de duplicidade dentro do tenant
    # ---------------------------------------------------------------

    existing_user = db.scalar(
        select(User).where(
            User.tenant_id == current_user.tenant_id,
            User.email == email,
        )
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Não foi possível criar o usuário",
        )

    # ---------------------------------------------------------------
    # 3. Hash da senha
    # ---------------------------------------------------------------

    try:
        password_hash = password_hasher.hash(payload.password)
    except HashingError:
        # Não expor detalhes internos do mecanismo de hashing.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível criar o usuário",
        )

    # ---------------------------------------------------------------
    # 4. Criação do registro
    # ---------------------------------------------------------------

    user = User(
        id=uuid4(),
        tenant_id=current_user.tenant_id,
        name=name,
        email=email,
        password_hash=password_hash,
        created_at=datetime.now(timezone.utc),
    )

    db.add(user)

    # ---------------------------------------------------------------
    # 5. Commit protegido contra condição de corrida
    # ---------------------------------------------------------------

    try:
        db.commit()
        db.refresh(user)

    except IntegrityError:
        db.rollback()

        # A constraint UNIQUE no banco é a proteção definitiva contra
        # duas requisições concorrentes criando o mesmo e-mail.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Não foi possível criar o usuário",
        )

    # ---------------------------------------------------------------
    # 6. Resposta explícita
    # ---------------------------------------------------------------

    # Não serializamos o objeto ORM inteiro.
    # Dessa forma password_hash, tenant_id e outros campos internos
    # não são acidentalmente expostos.
    return UserResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        created_at=user.created_at,
    )
