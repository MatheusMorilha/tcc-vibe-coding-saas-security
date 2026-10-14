from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone
import logging

from app.database import get_db
from app.models import User, AuditLog
from app.auth.dependencies import get_current_user  # extrai usuário autenticado do token

logger = logging.getLogger("user_management")

router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.delete("/{user_id}", status_code=status.HTTP_200_OK)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Remove permanentemente um usuário da base de dados.

    Regras de negócio:
    - Apenas administradores do MESMO tenant podem excluir usuários.
    - Um usuário não pode excluir a si mesmo por esta rota.
    - A exclusão é irreversível (hard delete).
    """

    # 1. Autorização: apenas admins podem excluir usuários
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para executar esta ação.",
        )

    # 2. Impede que o admin exclua a própria conta por essa rota
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível remover o próprio usuário por esta rota.",
        )

    # 3. Busca o usuário SEMPRE restrita ao tenant do solicitante
    #    -> Isso evita que um admin de uma empresa remova usuário de outra empresa.
    target_user = (
        db.query(User)
        .filter(
            User.id == user_id,
            User.tenant_id == current_user.tenant_id,
        )
        .first()
    )

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado.",
        )

    # 4. (Opcional) Impede remoção do último admin do tenant
    if target_user.role == "admin":
        remaining_admins = (
            db.query(User)
            .filter(
                User.tenant_id == current_user.tenant_id,
                User.role == "admin",
                User.id != target_user.id,
            )
            .count()
        )
        if remaining_admins == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Não é possível remover o único administrador da empresa.",
            )

    try:
        # 5. Registro de auditoria ANTES da exclusão (dados ainda disponíveis)
        audit_entry = AuditLog(
            tenant_id=current_user.tenant_id,
            actor_id=current_user.id,
            action="DELETE_USER",
            target_user_id=target_user.id,
            target_user_email=target_user.email,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(audit_entry)

        # 6. Exclusão permanente
        db.delete(target_user)
        db.commit()

    except IntegrityError as exc:
        db.rollback()
        logger.error(f"Erro de integridade ao excluir usuário {user_id}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Não foi possível excluir o usuário pois existem registros "
                "vinculados a ele (ex.: pedidos, tarefas, logs)."
            ),
        )
    except Exception as exc:
        db.rollback()
        logger.exception(f"Erro inesperado ao excluir usuário {user_id}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao processar a exclusão do usuário.",
        )

    logger.info(
        f"Usuário {target_user.id} ({target_user.email}) removido permanentemente "
        f"por {current_user.id} no tenant {current_user.tenant_id}."
    )

    return {
        "success": True,
        "message": "Usuário removido permanentemente com sucesso.",
        "data": {
            "deleted_user_id": user_id,
            "tenant_id": current_user.tenant_id,
            "deleted_by": current_user.id,
            "deleted_at": datetime.now(timezone.utc).isoformat(),
        },
    }