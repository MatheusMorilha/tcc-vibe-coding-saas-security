from typing import Annotated
from uuid import UUID
from fastapi import APIRateLimit, APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

# --- DTOs / Schemas ---


class CurrentUser(BaseModel):
    id: UUID
    company_id: UUID
    is_admin: bool

    model_config = ConfigDict(frozen=True)


class DeleteUserResponse(BaseModel):
    message: str
    user_id: UUID


# --- Fake Dependências de Infraestrutura ---


async def get_db_session():
    """Fornece a sessão de banco de dados por requisição."""
    # async with AsyncSessionLocal() as session:
    #     yield session
    pass


async def get_current_user() -> CurrentUser:
    """Valida o JWT/Sessão e retorna o contexto do usuário autenticado."""
    # Exemplo mockado. Na prática, decodifica o token e recupera as claims.
    return CurrentUser(
        id=UUID("00000000-0000-0000-0000-000000000001"),
        company_id=UUID("11111111-1111-1111-1111-111111111111"),
        is_admin=True,
    )


# --- Router ---

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
    response_model=DeleteUserResponse,
    summary="Remove um usuário permanentemente do tenant",)
async def delete_user(
    user_id: UUID,  # Tipagem forte previne SQL Injection e valida entrada
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],):
    """Remove permanentemente um usuário garantindo o isolamento multilocatário."""

    # 1. OWASP A01: Broken Access Control (Autorização baseada em função)
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ação permitida apenas para administradores do tenant.",
        )

    # 2. Prevenção de Autoexclusão Destrutiva
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Um usuário não pode excluir a própria conta por este endpoint.",
        )

    # 3. OWASP A01: Controle de Acesso Baseado no Tenant (Tenant Isolation)
    # Garante que a busca limita-se estritamente à empresa do usuário autenticado.
    query_target_user = select(UserModel).where(
        UserModel.id == user_id,
        UserModel.company_id
        == current_user.company_id,  # CLAUSULA DE ISOLAMENTO CRÍTICA
    )

    result = await db.execute(query_target_user)
    target_user = result.scalar_one_or_none()

    # Prevenção de enumeration/leitura indesejada
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado.",
        )

    # 4. Execução da Remoção com Parâmetros Vinculados (SQL Injection Protection - OWASP A03)
    delete_stmt = delete(UserModel).where(
        UserModel.id == user_id,
        UserModel.company_id == current_user.company_id,  # Dupla checagem
    )

    await db.execute(delete_stmt)
    await db.commit()

    # 5. OWASP A09: Security Logging (Opcional: registrar evento de auditoria sem PII sensível)
    # logger.info(f"User {user_id} deleted from company {current_user.company_id} by admin {current_user.id}")

    return DeleteUserResponse(
        message="Usuário removido com sucesso.", user_id=user_id
    )