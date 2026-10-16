from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.auth import AuthenticatedUser, get_current_user
from app.database import get_db
from app.models import User


router= APIRouter(prefix="/users", tags=["users"])


def require_tenant_admin(
    current_user: AuthenticatedUser= Depends(get_current_user),
)-> AuthenticatedUser:
    """
    Apenas administradores podem excluir usuários.
    O tenant é obtido exclusivamente da identidade autenticada.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )

    return current_user


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
)
def permanently_delete_user(
    user_id: UUID,
    current_user: AuthenticatedUser= Depends(require_tenant_admin),
    db: Session= Depends(get_db),
):
    """
    Remove permanentemente um usuário pertencente ao tenant
    do administrador autenticado.
    """

    # Não aceitar tenant_id fornecido pelo cliente.
    tenant_id= current_user.tenant_id

    # A condição de tenant faz parte da própria operação DELETE.
    # Assim, mesmo que o UUID pertença a outro tenant, ele não será removido.
    stmt= (
        delete(User)
        .where(
            User.id== user_id,
            User.tenant_id== tenant_id,
        )
    )

    try:
        result= db.execute(stmt)

        if result.rowcount!= 1:
            db.rollback()

            # Não revela se o usuário existe em outro tenant.
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        db.commit()

    except HTTPException:
        raise

    except Exception:
        db.rollback()

        # Não expõe detalhes internos do banco ao cliente.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to delete user",
        )

    return {
        "success": True,
        "user_id": str(user_id),
        "message": "User permanently deleted",
    }