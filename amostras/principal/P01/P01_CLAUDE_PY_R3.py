"""
Rota de API para exclusão permanente de usuário em plataforma SaaS multilocatária.

Stack de exemplo: FastAPI + SQLAlchemy (Session síncrona).
Adapte os imports de modelos/dependências ao seu projeto real.

Pontos de segurança tratados aqui (essenciais em multi-tenant):
1. Autenticação obrigatória (quem está chamando precisa estar logado).
2. Autorização por papel (somente admin da empresa, ou admin de plataforma).
3. Isolamento de tenant: o usuário alvo só pode ser excluído se pertencer
   ao MESMO tenant/empresa de quem faz a requisição (evita IDOR entre empresas).
4. Proteção contra autoexclusão indevida / exclusão do último admin da empresa.
5. Operação transacional (tudo ou nada).
6. Log de auditoria da exclusão (LGPD/GDPR: registrar quem, quando, o quê).
7. Resposta de confirmação clara, sem vazar dados sensíveis desnecessários.
"""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

# ---------------------------------------------------------------------------
# Dependências do projeto (ajuste conforme sua base de código real)
# ---------------------------------------------------------------------------
from app.database import get_db
from app.models import User, AuditLog
from app.auth.dependencies import get_current_user  # extrai usuário autenticado do token

router = APIRouter(prefix="/api/v1/users", tags=["users"])


# ---------------------------------------------------------------------------
# Schemas de resposta
# ---------------------------------------------------------------------------
class UserDeletionResponse(BaseModel):
    success: bool
    message: str
    deleted_user_id: UUID
    deleted_at: datetime


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------
@router.delete(
    "/{user_id}",
    response_model=UserDeletionResponse,
    status_code=status.HTTP_200_OK,
    summary="Remove permanentemente um usuário da base de dados",
)
def delete_user(
    user_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserDeletionResponse:
    """
    Exclui permanentemente (hard delete) um usuário da base.

    Regras de negócio/segurança aplicadas:
    - Apenas administradores da própria empresa (ou super admin de plataforma)
      podem executar esta ação.
    - O usuário alvo deve pertencer ao mesmo tenant (company_id) de quem faz
      a chamada — a menos que seja um super admin de plataforma.
    - Não é permitido remover o último administrador ativo da empresa.
    """

    # 1) Autorização: apenas admin da empresa ou super admin de plataforma
    if current_user.role not in ("company_admin", "platform_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para remover usuários.",
        )

    # 2) Busca o usuário alvo
    target_user = db.query(User).filter(User.id == user_id).first()

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado.",
        )

    # 3) Isolamento de tenant — regra crítica em multi-tenant.
    #    Um company_admin só pode excluir usuários da própria empresa.
    #    Apenas platform_admin pode atravessar tenants (ex.: suporte técnico).
    if current_user.role == "company_admin" and (
        target_user.company_id != current_user.company_id
    ):
        # Retornar 404 (em vez de 403) evita vazar a existência do usuário
        # em outro tenant para quem não tem acesso a ele.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado.",
        )

    # 4) Impede remover a si mesmo por este endpoint (evita lockout acidental)
    if target_user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível remover o próprio usuário por esta rota.",
        )

    # 5) Impede remover o último administrador ativo da empresa
    if target_user.role == "company_admin":
        remaining_admins = (
            db.query(User)
            .filter(
                User.company_id == target_user.company_id,
                User.role == "company_admin",
                User.id != target_user.id,
                User.is_active.is_(True),
            )
            .count()
        )
        if remaining_admins == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Não é possível remover o único administrador da empresa.",
            )

    # 6) Executa exclusão de forma transacional, com log de auditoria
    deleted_at = datetime.now(timezone.utc)
    try:
        audit_entry = AuditLog(
            action="user_deleted",
            actor_id=current_user.id,
            actor_company_id=current_user.company_id,
            target_user_id=target_user.id,
            target_company_id=target_user.company_id,
            metadata={
                "target_email": target_user.email,
                "target_role": target_user.role,
            },
            created_at=deleted_at,
        )
        db.add(audit_entry)

        db.delete(target_user)
        db.commit()

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao remover o usuário. A operação foi revertida.",
        )

    # 7) Confirmação da operação
    return UserDeletionResponse(
        success=True,
        message="Usuário removido permanentemente com sucesso.",
        deleted_user_id=user_id,
        deleted_at=deleted_at,
    )