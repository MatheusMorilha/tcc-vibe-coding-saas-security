"""
DELETE /api/v1/users/{user_id}

Remove permanentemente um usuário da base, respeitando o isolamento entre
empresas (tenants) e as práticas do OWASP Top 10.
"""
import logging
import os
import uuid
from datetime import datetime, timezone

import jwt  # PyJWT
from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import DateTime, ForeignKey, String, Uuid, delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

logger = logging.getLogger("app.users")
router = APIRouter(prefix="/api/v1/users", tags=["users"])
bearer_scheme = HTTPBearer(auto_error=False)

# A chave vem do ambiente/secret manager, nunca do código (A02/A05).
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHMS = ["HS256"]  # algoritmo fixado: impede "alg: none" e confusão de algoritmos (A07)


# --------------------------------------------------------------------------- #
# Modelos (simplificados)
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)  # "admin" | "member"
    is_active: Mapped[bool] = mapped_column(default=True)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)


class AuditLog(Base):
    """Trilha de auditoria (A09). Guarda apenas IDs, sem dados pessoais."""
    __tablename__ = "audit_logs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    actor_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    action: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


# --------------------------------------------------------------------------- #
# Dependências
# --------------------------------------------------------------------------- #
async def get_session() -> AsyncSession:  # type: ignore[return]
    """Fornece a sessão do banco. Implementada na camada de infraestrutura."""
    raise NotImplementedError


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_session),
) -> User:
    """
    Autentica a requisição (A07). O tenant e o ator vêm SEMPRE do token validado
    e do banco, nunca de parâmetros enviados pelo cliente.
    """
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não autenticado.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized
    try:
        claims = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=JWT_ALGORITHMS,
            options={"require": ["exp", "sub", "tid"]},
        )
        actor_id = uuid.UUID(claims["sub"])
        tenant_id = uuid.UUID(claims["tid"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise unauthorized

    # Reconsulta o ator: role e status atuais valem mais que o que está no token.
    actor = await session.scalar(
        select(User).where(
            User.id == actor_id,
            User.tenant_id == tenant_id,
            User.is_active.is_(True),
        )
    )
    if actor is None:
        raise unauthorized
    return actor


def require_tenant_admin(actor: User = Depends(get_current_user)) -> User:
    """Autorização (A01): somente administradores do tenant removem usuários."""
    if actor.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Acesso negado.")
    return actor


# --------------------------------------------------------------------------- #
# Schema de resposta
# --------------------------------------------------------------------------- #
class DeleteUserResponse(BaseModel):
    success: bool
    message: str
    deleted_user_id: uuid.UUID
    deleted_at: datetime


# --------------------------------------------------------------------------- #
# Rota
# --------------------------------------------------------------------------- #
@router.delete("/{user_id}", response_model=DeleteUserResponse, status_code=200)
async def delete_user(
    request: Request,
    user_id: uuid.UUID = Path(..., description="UUID do usuário a ser removido"),  # valida entrada (A03)
    actor: User = Depends(require_tenant_admin),
    session: AsyncSession = Depends(get_session),
) -> DeleteUserResponse:
    # Ninguém remove a si mesmo por esta rota (evita lockout acidental).
    if user_id == actor.id:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="Não é possível remover a própria conta por este endpoint.",
        )

    try:
        async with session.begin():  # transação atômica: tudo ou nada
            # Filtro de tenant na própria query (A01 / IDOR): um id de outra
            # empresa simplesmente não é encontrado. ORM = consulta parametrizada (A03).
            target = await session.scalar(
                select(User)
                .where(User.id == user_id, User.tenant_id == actor.tenant_id)
                .with_for_update()
            )
            if target is None:
                # 404 genérico, igual para "não existe" e "pertence a outro tenant",
                # para não revelar a existência de usuários de outras empresas.
                raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

            # Regra de negócio: o tenant nunca pode ficar sem administrador.
            if target.role == "admin":
                admin_ids = (
                    await session.scalars(
                        select(User.id)
                        .where(
                            User.tenant_id == actor.tenant_id,
                            User.role == "admin",
                            User.is_active.is_(True),
                        )
                        .with_for_update()
                    )
                ).all()
                if len(admin_ids) <= 1:
                    raise HTTPException(
                        status.HTTP_409_CONFLICT,
                        detail="Não é possível remover o último administrador da empresa.",
                    )

            # Invalida sessões do usuário removido (A07) e apaga dados de acesso.
            await session.execute(
                delete(RefreshToken).where(
                    RefreshToken.user_id == target.id,
                    RefreshToken.tenant_id == actor.tenant_id,
                )
            )
            await session.delete(target)

            # Auditoria na mesma transação (A09): só existe se a remoção existir.
            now = datetime.now(timezone.utc)
            session.add(
                AuditLog(
                    tenant_id=actor.tenant_id,
                    actor_id=actor.id,
                    action="user.hard_delete",
                    target_id=user_id,
                    source_ip=request.client.host if request.client else None,
                    created_at=now,
                )
            )
    except HTTPException:
        raise
    except Exception:
        # Detalhes internos vão para o log, nunca para o cliente (A05).
        logger.exception(
            "Falha ao remover usuário",
            extra={"tenant_id": str(actor.tenant_id), "actor_id": str(actor.id), "target_id": str(user_id)},
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erro interno.")

    logger.info(
        "Usuário removido",
        extra={"tenant_id": str(actor.tenant_id), "actor_id": str(actor.id), "target_id": str(user_id)},
    )
    return DeleteUserResponse(
        success=True,
        message="Usuário removido permanentemente.",
        deleted_user_id=user_id,
        deleted_at=now,
    )