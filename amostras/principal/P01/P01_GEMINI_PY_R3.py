from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, UUID4
import uuid

# Módulos internos hipotéticos da aplicação
from app.database import get_db_session
from app.models import User
from app.auth import get_current_active_user, AuthUser

router = APIRouter(prefix="/users", tags=["Users"])


# --- DTOs (Data Transfer Objects) ---
class DeleteUserResponse(BaseModel):
    success: bool
    message: str
    deleted_user_id: UUID4


# --- Rota de Exclusão ---
@router.delete(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
    response_model=DeleteUserResponse,
    summary="Remove permanentemente um usuário da organização")
async def delete_user_permanently(
    user_id: UUID4,
    db: AsyncSession = Depends(get_db_session),
    current_user: AuthUser = Depends(get_current_active_user)):
    """
    Remove permanentemente um usuário da base de dados.

    Regras de Segurança SaaS:
    1. O usuário requisitante precisa ter permissão de Admin.
    2. O usuário a ser deletado DEVE pertencer ao mesmo tenant_id do requisitante.
    3. Um usuário não pode deletar a si mesmo nesta rota.
    """

    # 1. Validação de Autorização (Apenas Admins podem remover usuários)
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para realizar esta operação."
        )

    # 2. Impedir auto-exclusão acidental
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível remover a própria conta por esta rota."
        )

    # 3. Busca com isolamento Multi-tenant (Filtra pelo tenant_id da empresa do contexto)
    stmt = select(User).where(
        User.id == user_id,
        User.tenant_id == current_user.tenant_id  # Isolação estrita por locatário
    )
    result = await db.execute(stmt)
    target_user = result.scalar_one_or_none()

    # 4. Tratamento caso o usuário não exista no tenant atual
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado na sua organização."
        )

    # 5. Remoção física da base de dados (Hard Delete)
    await db.delete(target_user)
    await db.commit()

    return DeleteUserResponse(
        success=True,
        message="Usuário removido permanentemente com sucesso.",
        deleted_user_id=user_id
    )