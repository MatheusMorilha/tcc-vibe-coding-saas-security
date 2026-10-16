# app/routes/users.py
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import AuthenticatedUser, get_current_user  # valida JWT/sessão
from app.db import get_session
from app.models import AuditLog, User

logger = logging.getLogger("app.users")
limiter = Limiter(key_func=get_remote_address)
router = APIRouter(prefix="/api/v1/users", tags=["users"])


class DeleteUserResponse(BaseModel):
    user_id: uuid.UUID
    deleted: bool
    deleted_at: datetime


def require_tenant_admin(
    current: AuthenticatedUser = Depends(get_current_user),
) -> AuthenticatedUser:
    """Autorização: somente administradores do próprio tenant."""
    if current.role != "admin":
        # Mensagem genérica; não detalha a regra interna.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Operação não permitida.")
    return current


@router.delete(
    "/{user_id}",
    response_model=DeleteUserResponse,
    status_code=status.HTTP_200_OK,
)
@limiter.limit("10/minute")
async def delete_user(
    request: Request,  # exigido pelo slowapi
    user_id: uuid.UUID,  # validação de formato: bloqueia entradas malformadas
    current: AuthenticatedUser = Depends(require_tenant_admin),
    session: AsyncSession = Depends(get_session),
) -> DeleteUserResponse:
    # Regra de negócio: não permitir auto-exclusão.
    if user_id == current.id:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Não é possível remover a própria conta por esta rota.",
        )

    try:
        async with session.begin():
            # A01: tenant_id SEMPRE vem do token, nunca do cliente.
            # FOR UPDATE serializa exclusões concorrentes (anti race condition).
            target = (
                await session.execute(
                    select(User)
                    .where(User.id == user_id, User.tenant_id == current.tenant_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()

            # 404 tanto para "não existe" quanto para "é de outro tenant":
            # evita enumeração de IDs entre empresas.
            if target is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuário não encontrado.")

            # Não deixar o tenant sem nenhum administrador.
            if target.role == "admin":
                admin_count = (
                    await session.execute(
                        select(func.count())
                        .select_from(User)
                        .where(
                            User.tenant_id == current.tenant_id,
                            User.role == "admin",
                        )
                        .with_for_update()
                    )
                ).scalar_one()
                if admin_count <= 1:
                    raise HTTPException(
                        status.HTTP_409_CONFLICT,
                        "Não é possível remover o último administrador da empresa.",
                    )

            deleted_at = datetime.now(timezone.utc)

            # Exclusão permanente, novamente com filtro de tenant (defesa em profundidade).
            await session.execute(
                delete(User).where(
                    User.id == user_id, User.tenant_id == current.tenant_id
                )
            )

            # A09: trilha de auditoria na MESMA transação (atomicidade).
            # Sem PII: apenas identificadores.
            session.add(
                AuditLog(
                    tenant_id=current.tenant_id,
                    actor_id=current.id,
                    action="user.delete",
                    target_id=user_id,
                    ip=request.client.host if request.client else None,
                    created_at=deleted_at,
                )
            )
    except HTTPException:
        raise
    except Exception:
        # A05/A09: log interno detalhado; resposta genérica ao cliente.
        logger.exception(
            "Falha ao remover usuário",
            extra={"tenant_id": str(current.tenant_id), "actor_id": str(current.id)},
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Erro interno ao processar a solicitação.",
        )

    logger.info(
        "user.delete",
        extra={
            "tenant_id": str(current.tenant_id),
            "actor_id": str(current.id),
            "target_id": str(user_id),
        },
    )

    return DeleteUserResponse(user_id=user_id, deleted=True, deleted_at=deleted_at)