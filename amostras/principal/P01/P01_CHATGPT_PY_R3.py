from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

app = FastAPI()


# Exemplo de modelos/repositório já existentes na aplicação.
class User:
    id: int
    tenant_id: int


class CurrentUser:
    id: int
    tenant_id: int
    is_admin: bool


async def get_db() -> AsyncSession:
    ...


async def get_current_user() -> CurrentUser:
    ...


class DeleteUserResponse(BaseModel):
    success: bool
    user_id: int
    message: str


@app.delete(
    "/users/{user_id}",
    response_model=DeleteUserResponse,
    status_code=200,
)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    # Apenas usuários autorizados podem excluir outros usuários.
    if not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Usuário sem permissão para excluir usuários.",
        )

    # O usuário precisa pertencer ao mesmo tenant do administrador.
    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.tenant_id == current_user.tenant_id,
        )
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="Usuário não encontrado.",
        )

    # Exclusão permanente, restrita ao tenant autenticado.
    await db.execute(
        delete(User).where(
            User.id == user_id,
            User.tenant_id == current_user.tenant_id,
        )
    )

    await db.commit()

    return DeleteUserResponse(
        success=True,
        user_id=user_id,
        message="Usuário removido permanentemente.",
    )
