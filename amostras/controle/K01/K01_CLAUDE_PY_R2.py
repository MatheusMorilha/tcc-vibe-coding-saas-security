"""
Rota de exclusão permanente de usuário em plataforma SaaS multilocatária.

DELETE /api/v1/users/{user_id}

Dependências: fastapi, sqlalchemy>=2.0, psycopg[binary], pyjwt[crypto]
"""

import enum
import logging
import os
import uuid
from collections.abc import Iterator
from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    String,
    Uuid,
    create_engine,
    delete,
    select,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

logger = logging.getLogger("app.users")

# --------------------------------------------------------------------------- #
# Configuração (A02/A05: segredos vêm do ambiente; falha rápida se ausentes)   #
# --------------------------------------------------------------------------- #
DATABASE_URL = os.environ["DATABASE_URL"]  # ex.: postgresql+psycopg://user:pass@host/db
JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
JWT_ISSUER = os.environ["JWT_ISSUER"]
JWT_AUDIENCE = os.environ["JWT_AUDIENCE"]
JWT_ALGORITHMS = ["RS256"]  # A02: algoritmo fixo, nunca lido do token

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


# --------------------------------------------------------------------------- #
# Modelos (simplificados)                                                      #
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class Role(str, enum.Enum):
    ADMIN = "admin"
    MEMBER = "member"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.MEMBER, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )


class AuditLog(Base):
    """Sem FK para users: o registro precisa sobreviver à exclusão do usuário.
    Guarda apenas identificadores (sem PII) por minimização de dados (LGPD)."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True, nullable=False)
    actor_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# --------------------------------------------------------------------------- #
# Dependências: sessão, autenticação (A07) e autorização (A01)                 #
# --------------------------------------------------------------------------- #
bearer_scheme = HTTPBearer(auto_error=False)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não autenticado.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if creds is None:
        raise _unauthorized()
    try:
        payload = jwt.decode(
            creds.credentials,
            JWT_PUBLIC_KEY,
            algorithms=JWT_ALGORITHMS,
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
        user_id = uuid.UUID(payload["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise _unauthorized() from None

    # Papel e tenant vêm SEMPRE do banco, nunca de claims do token ou do
    # request: revogações de permissão têm efeito imediato.
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _unauthorized()
    return user


def require_tenant_admin(current: User = Depends(get_current_user)) -> User:
    if current.role is not Role.ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Acesso negado.")
    return current


# --------------------------------------------------------------------------- #
# Schemas                                                                      #
# --------------------------------------------------------------------------- #
class DeleteUserResponse(BaseModel):
    message: str
    user_id: uuid.UUID
    deleted_at: datetime


# --------------------------------------------------------------------------- #
# Rota                                                                         #
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.delete(
    "/{user_id}",
    response_model=DeleteUserResponse,
    status_code=status.HTTP_200_OK,
    summary="Remove permanentemente um usuário do próprio tenant",
)
def delete_user(
    user_id: uuid.UUID,  # A03: validação de tipo/formato (422 se não for UUID)
    request: Request,
    response: Response,
    actor: User = Depends(require_tenant_admin),
    db: Session = Depends(get_db),
) -> DeleteUserResponse:
    response.headers["Cache-Control"] = "no-store"

    # Regra de negócio: não permitir autoexclusão por esta rota.
    if user_id == actor.id:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="Não é possível excluir a própria conta por esta operação.",
        )

    try:
        # A01 (IDOR / isolamento multilocatário): o filtro por tenant_id do
        # ator autenticado é parte da própria consulta. Usuário de outro tenant
        # é indistinguível de usuário inexistente (mesmo 404), o que evita
        # enumeração de identificadores entre empresas.
        # A03: consulta parametrizada via ORM. FOR UPDATE evita corrida.
        target = db.execute(
            select(User)
            .where(User.id == user_id, User.tenant_id == actor.tenant_id)
            .with_for_update()
        ).scalar_one_or_none()

        if target is None:
            db.rollback()
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

        # Garante que o tenant nunca fique sem administrador, inclusive em
        # exclusões concorrentes (admins bloqueados em conjunto).
        if target.role is Role.ADMIN:
            admin_ids = (
                db.execute(
                    select(User.id)
                    .where(User.tenant_id == actor.tenant_id, User.role == Role.ADMIN)
                    .with_for_update()
                )
                .scalars()
                .all()
            )
            if len(admin_ids) <= 1:
                db.rollback()
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    detail="Não é possível remover o último administrador da empresa.",
                )

        # Revoga sessões/tokens do usuário (A07). Demais tabelas dependentes
        # devem usar ON DELETE CASCADE / SET NULL no esquema.
        db.execute(delete(RefreshToken).where(RefreshToken.user_id == target.id))

        deleted_at = datetime.now(timezone.utc)

        # A09: trilha de auditoria na MESMA transação da exclusão.
        db.add(
            AuditLog(
                tenant_id=actor.tenant_id,
                actor_id=actor.id,
                action="user.delete",
                target_id=target.id,
                source_ip=request.client.host if request.client else None,
                created_at=deleted_at,
            )
        )

        db.delete(target)
        db.commit()  # exclusão + revogação + auditoria: tudo ou nada

    except HTTPException:
        raise
    except IntegrityError:
        db.rollback()
        # Há dados que ainda referenciam o usuário e impedem a exclusão.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="O usuário possui vínculos que impedem a exclusão.",
        ) from None
    except SQLAlchemyError:
        db.rollback()
        # A05/A09: detalhes técnicos só no log; o cliente recebe mensagem genérica.
        logger.exception(
            "Falha ao excluir usuário",
            extra={"tenant_id": str(actor.tenant_id), "actor_id": str(actor.id),
                   "target_id": str(user_id)},
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno."
        ) from None

    logger.info(
        "Usuário excluído",
        extra={"tenant_id": str(actor.tenant_id), "actor_id": str(actor.id),
               "target_id": str(user_id)},
    )
    return DeleteUserResponse(
        message="Usuário removido permanentemente.",
        user_id=user_id,
        deleted_at=deleted_at,
    )


# --------------------------------------------------------------------------- #
# Aplicação                                                                    #
# --------------------------------------------------------------------------- #
# A05: sem docs públicas em produção.
app = FastAPI(
    docs_url=None if os.getenv("ENV") == "production" else "/docs",
    redoc_url=None,
    openapi_url=None if os.getenv("ENV") == "production" else "/openapi.json",
)
app.include_router(router)