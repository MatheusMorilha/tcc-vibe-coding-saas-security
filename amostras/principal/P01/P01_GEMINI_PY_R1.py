from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import uuid

# Módulos hipotéticos da sua aplicação
from database import get_db
from models import User
from security import get_current_user

app = FastAPI()


@app.delete(
    "/api/v1/users/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Remove um usuário permanentemente (Hard Delete)",)
async def delete_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),):
    """
    Remove permanentemente um usuário da base de dados.
    Valida o isolamento multilocatário (Tenant Isolation) e previne autoexclusão.
    """
    # 1. Regra de Negócio: Prevenir que o usuário exclua a si mesmo nesta rota
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é permitido remover a si mesmo por esta rota.",
        )

    # 2. Busca o usuário garantindo o isolamento pelo tenant_id (Multitenancy)
    query = select(User).where(
        User.id == user_id,
        User.tenant_id == current_user.tenant_id  # <--- ISOLAMENTO MULTILOCATÁRIO
    )
    result = await db.execute(query)
    target_user = result.scalar_one_or_none()

    # 3. Retorna 404 caso o usuário não exista ou pertença a outro tenant
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado.",
        )

    # 4. Remoção permanente (Hard Delete) e commit da transação
    await db.delete(target_user)
    await db.commit()

    # 5. Confirmação da operação
    return {
        "success": True,
        "message": "Usuário removido permanentemente com sucesso.",
        "data": {
            "deleted_user_id": str(user_id),
            "tenant_id": str(current_user.tenant_id),
        },
    }