"""
Rota de API para exclusão permanente de usuário em plataforma SaaS
multilocatária (multi-tenant).

Stack: FastAPI + SQLAlchemy (síncrono, mas o mesmo padrão vale para
async). Ajuste os imports de modelos/dependências conforme o projeto
real.

Pontos de segurança tratados aqui, essenciais em ambiente multi-tenant
com dados de todas as empresas na mesma base:

1. Autenticação obrigatória (get_current_user).
2. Autorização: apenas admin do tenant (ou o próprio usuário) pode
   excluir.
3. Isolamento de tenant: a query SEMPRE filtra por tenant_id, nunca
   busca o usuário só pelo ID. Isso evita que alguém da Empresa A
   apague um usuário da Empresa B trocando o ID na URL (IDOR).
4. Exclusão permanente é irreversível -> log de auditoria antes de
   remover, e tratamento de erro/transação.
5. Regra de negócio: impedir que o último admin de um tenant se
   autoexclua, deixando a empresa sem administrador.
"""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

# --- Ajustar conforme a estrutura real do projeto -----------------------
from app.database import get_db
from app.models import User, AuditLog
from app.auth.dependencies import get_current_user
# -------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/users", tags=["users"])


class UserDeleteResponse(BaseModel):
    success: bool
    message: str
    user_id: UUID
    deleted_at: datetime


def _ensure_can_delete(current_user: User, target_user: User) -> None:
    """Regras de autorização para exclusão de usuário."""

    # Isolamento de tenant: nunca deixar operar fora da própria empresa.
    if current_user.tenant_id != target_user.tenant_id:
        # Retorna 404 (e não 403) para não revelar a existência do
        # recurso em outro tenant.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado.",
        )

    # Apenas admin do tenant ou o próprio usuário podem excluir.
    is_self = current_user.id == target_user.id
    is_tenant_admin = current_user.role == "admin"

    if not (is_self or is_tenant_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para remover este usuário.",
        )

    # Impede remover o último admin do tenant (evita empresa órfã).
    if target_user.role == "admin":
        remaining_admins = (
            target_user.tenant.users.filter_by(role="admin")
            .filter(User.id != target_user.id)
            .count()
        )
        if remaining_admins == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Não é possível remover o único administrador "
                    "da empresa."
                ),
            )


@router.delete("/{user_id}", response_model=UserDeleteResponse)
def delete_user(
    user_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserDeleteResponse:
    """
    Remove permanentemente um usuário da base de dados.

    A busca já nasce filtrada pelo tenant do usuário autenticado,
    então um ID de usuário de outra empresa nunca é sequer localizado
    por esta consulta.
    """
    target_user = (
        db.query(User)
        .filter(
            User.id == user_id,
            User.tenant_id == current_user.tenant_id,
        )
        .first()
    )

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado.",
        )

    _ensure_can_delete(current_user, target_user)

    deleted_at = datetime.now(timezone.utc)

    try:
        # Log de auditoria antes da remoção física — operação é
        # irreversível, então registrar quem fez, quando e o alvo.
        db.add(
            AuditLog(
                tenant_id=current_user.tenant_id,
                actor_id=current_user.id,
                action="user.delete",
                target_id=target_user.id,
                metadata={"target_email": target_user.email},
                created_at=deleted_at,
            )
        )

        db.delete(target_user)
        db.commit()

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao remover o usuário. Nenhuma alteração foi salva.",
        )

    return UserDeleteResponse(
        success=True,
        message="Usuário removido permanentemente.",
        user_id=user_id,
        deleted_at=deleted_at,
    )