from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.future import select
from typing import NamedTuple

# Suponha que estes módulos venham da arquitetura do seu projeto
from database import get_db
from models import User
from auth import get_current_user  # Middleware/Injeção que extrai o usuário da sessão/JWT

router = APIRouter(prefix="/users", tags=["Users"])


# Estrutura auxiliar do usuário logado (token JWT tipicamente contém id e tenant_id)
class CurrentUserContext(NamedTuple):
    id: str
    tenant_id: str
    is_admin: bool


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Remove permanentemente um usuário da organização",)
def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: CurrentUserContext = Depends(get_current_user),):
    """
    Remove permanentemente um usuário da base de dados.
    Garante isolamento multilocatário (Tenant Isolation) e autorização de escopo.
    """
    # 1. Regra de Negócio / Autorização: Apenas administradores podem remover usuários
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não possui permissão para excluir usuários desta organização.",
        )

    # 2. Regra de Negócio: Previne que o administrador exclua a si próprio diretamente por este endpoint
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível remover o próprio usuário autenticado.",
        )

    # 3. Busca do Usuário aplicando estritamente a trava de Tenant Isolation
    stmt = select(User).where(
        User.id == user_id,
        User.tenant_id == current_user.tenant_id  # <--- ISOLAMENTO MULTILOCATÁRIO
    )
    user = db.execute(stmt).scalar_one_or_none()

    # 4. Tratamento de não encontrado (retorna 404 tanto se não existir quanto se for de outro tenant)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado na organização.",
        )

    # 5. Remoção física permanentemente do banco de dados (Hard Delete)
    try:
        db.delete(user)
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao processar a exclusão do usuário.",
        ) from exc

    # 6. Retorno de confirmação da operação
    return {
        "success": True,
        "message": "Usuário removido permanentemente com sucesso.",
        "deleted_user_id": user_id,
        "tenant_id": current_user.tenant_id,
    }