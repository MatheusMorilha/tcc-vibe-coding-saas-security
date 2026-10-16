from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete
from sqlalchemy.orm import Session

router= APIRouter(prefix="/users", tags=["users"])


@router.delete("/{user_id}", status_code=status.HTTP_200_OK)
def delete_user(
    user_id: int,
    db: Session= Depends(get_db),
    current_user: User= Depends(get_current_user),
):
    # Autorização: somente administradores do tenant podem excluir usuários.
    if not current_user.is_tenant_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operação não autorizada",
        )

    # Isolamento obrigatório entre tenants.
    stmt= (
        delete(User)
        .where(
            User.id== user_id,
            User.tenant_id== current_user.tenant_id,
        )
    )

    result= db.execute(stmt)

    if result.rowcount!= 1:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado",
        )

    db.commit()

    return {
        "success": True,
        "message": "Usuário removido permanentemente",
        "user_id": user_id,
    }