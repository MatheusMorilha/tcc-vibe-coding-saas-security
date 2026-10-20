
import os
from datetime import datetime, timezone
from typing import Annotated

from fastapi import (
    FastAPI, Depends, HTTPException, Query, status
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, String, Integer, DateTime, JSON,
    ForeignKey, select, desc
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column,
    Session, sessionmaker
)


# --------------------------------------------------
# Configuração
# --------------------------------------------------

DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]
JWT_ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False
)

app = FastAPI(title="SaaS - Gestão de Permissões")
bearer = HTTPBearer()

# Permissões reconhecidas pela aplicação.
ALLOWED_PERMISSIONS = {
    "users.read",
    "users.create",
    "users.update",
    "users.delete",
    "users.permissions.update",
    "reports.read",
    "billing.read",
}


class Base(DeclarativeBase):
    pass


# --------------------------------------------------
# Modelos de dados
# --------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )
    tenant_id: Mapped[int] = mapped_column(
        Integer, index=True, nullable=False
    )
    email: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    permissions: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )
    tenant_id: Mapped[int] = mapped_column(
        Integer, index=True, nullable=False
    )
    actor_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False
    )
    target_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False
    )
    action: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    before_state: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )
    after_state: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )


# Execute uma única vez durante a inicialização do projeto.
# Em produção, prefira migrations com Alembic.
# Base.metadata.create_all(engine)


# --------------------------------------------------
# Dependências
# --------------------------------------------------

def get_db():
    with SessionLocal() as db:
        yield db


DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials,
        Depends(bearer)
    ],
    db: DbSession,
) -> User:
    """Valida o JWT e carrega o usuário autenticado."""

    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )
        subject = payload.get("sub")
        if subject is None:
            raise HTTPException(
                status_code=401,
                detail="Token sem identificação do usuário",
            )
        user_id = int(subject)
    except (JWTError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Token inválido ou expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Usuário autenticado não encontrado",
        )

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_permission(user: User, permission: str) -> None:
    if permission not in user.permissions:
        raise HTTPException(
            status_code=403,
            detail="Você não possui autorização para esta operação",
        )


# --------------------------------------------------
# Contratos da API
# --------------------------------------------------

class UpdatePermissionsRequest(BaseModel):
    permissions: list[str] = Field(
        min_length=0,
        max_length=len(ALLOWED_PERMISSIONS),
    )


class UpdatePermissionsResponse(BaseModel):
    user_id: int
    tenant_id: int
    permissions: list[str]
    audit_id: int


class AuditEntryResponse(BaseModel):
    id: int
    tenant_id: int
    actor_user_id: int
    target_user_id: int
    action: str
    before_state: dict
    after_state: dict
    occurred_at: datetime


# --------------------------------------------------
# Alteração de permissões + auditoria
# --------------------------------------------------

@app.patch(
    "/users/{target_user_id}/permissions",
    response_model=UpdatePermissionsResponse,
)
def update_user_permissions(
    target_user_id: int,
    body: UpdatePermissionsRequest,
    db: DbSession,
    actor: CurrentUser,
):
    require_permission(actor, "users.permissions.update")

    # Rejeita permissões desconhecidas.
    requested = body.permissions
    if (
        len(requested) != len(set(requested))
        or not set(requested).issubset(ALLOWED_PERMISSIONS)
    ):
        raise HTTPException(
            status_code=422,
            detail="Lista contém permissões inválidas ou duplicadas",
        )

    # O tenant é sempre obtido do usuário autenticado.
    # A consulta nunca procura o alvo em outra empresa.
    with db.begin():
        target = db.scalar(
            select(User)
            .where(
                User.id == target_user_id,
                User.tenant_id == actor.tenant_id,
            )
            .with_for_update()
        )

        if target is None:
            raise HTTPException(
                status_code=404,
                detail="Usuário não encontrado nesta empresa",
            )

        before = sorted(target.permissions)
        after = sorted(requested)

        if before == after:
            raise HTTPException(
                status_code=409,
                detail="As permissões informadas já estão aplicadas",
            )

        target.permissions = after

        audit = AuditLog(
            tenant_id=actor.tenant_id,
            actor_user_id=actor.id,
            target_user_id=target.id,
            action="user.permissions.updated",
            before_state={"permissions": before},
            after_state={"permissions": after},
        )
        db.add(audit)
        db.flush()

        response = UpdatePermissionsResponse(
            user_id=target.id,
            tenant_id=actor.tenant_id,
            permissions=after,
            audit_id=audit.id,
        )

    # O contexto transacional confirma as duas gravações.
    # Em caso de erro, ambas são revertidas.
    return response


# --------------------------------------------------
# Consulta ao histórico de auditoria
# --------------------------------------------------

@app.get(
    "/audit-logs",
    response_model=list[AuditEntryResponse],
)
def list_audit_logs(
    db: DbSession,
    actor: CurrentUser,
    target_user_id: int | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    require_permission(actor, "users.permissions.update")

    statement = (
        select(AuditLog)
        .where(AuditLog.tenant_id == actor.tenant_id)
        .order_by(desc(AuditLog.occurred_at), desc(AuditLog.id))
    )

    if target_user_id is not None:
        statement = statement.where(
            AuditLog.target_user_id == target_user_id
        )

    entries = db.scalars(
        statement.limit(limit).offset(offset)
    ).all()

    return [
        AuditEntryResponse(
            id=entry.id,
            tenant_id=entry.tenant_id,
            actor_user_id=entry.actor_user_id,
            target_user_id=entry.target_user_id,
            action=entry.action,
            before_state=entry.before_state,
            after_state=entry.after_state,
            occurred_at=entry.occurred_at,
        )
        for entry in entries
    ]
