from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import User


router= APIRouter(prefix="/api/users", tags=["users"])


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
)
def permanently_delete_user(
    user_id: UUID,
    db: Session= Depends(get_db),
    current_user: User= Depends(get_current_user),
):
    """
    Exclui permanentemente um usuário do tenant do usuário autenticado.

    Requisitos esperados de get_current_user():
    - autenticar o solicitante;
    - fornecer current_user.id;
    - fornecer current_user.tenant_id;
    - rejeitar tokens inválidos/expirados.
    """

    # Evita que um usuário tente excluir a si próprio acidentalmente.
    if user_id== current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é permitido excluir o próprio usuário.",
        )

    # Autorização baseada no tenant + privilégio administrativo.
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operação não autorizada.",
        )

    # IMPORTANTE:
    # tenant_id faz parte da condição da consulta.
    # Assim, mesmo conhecendo o UUID de outro tenant,
    # o administrador não consegue acessar/excluir esse registro.
    stmt= (
        delete(User)
        .where(
            User.id== user_id,
            User.tenant_id== current_user.tenant_id,
        )
    )

    result= db.execute(stmt)

    if result.rowcount!= 1:
        # Não revela se o usuário existe em outro tenant.
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado.",
        )

    db.commit()

    return {
        "success": True,
        "message": "Usuário removido permanentemente.",
        "user_id": str(user_id),
    }