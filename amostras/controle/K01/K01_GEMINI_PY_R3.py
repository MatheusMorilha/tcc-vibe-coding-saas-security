from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, UUID4
from datetime import datetime
from typing import Optional

# Dependências de banco e segurança/autenticação da aplicação
from app.db.session import get_db
from app.auth.dependencies import get_current_user
from app.models.user import User, UserRole

router = APIRouter(prefix="/users", tags=["Users"])


# --- Schemas ---
class UserDeletionResponse(BaseModel):
    success: bool
    message: str
    deleted_user_id: UUID4
    timestamp: datetime


# --- Endpoint ---
@router.delete(
    "/{user_id}",
    response_model=UserDeletionResponse,
    status_code=status.HTTP_200_OK,
    summary="Remove um usuário permanentemente")
def delete_user(
    user_id: UUID4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    """
    Remove um usuário permanentemente mantendo o isolamento multilocatário (Tenant Isolation).

    OWASP Compliance:
    - A01: Broken Access Control (Validação estrita do tenant_id + RBAC)
    - A03: Injection (Consultas parametrizadas pelo ORM)
    - A09: Security Logging (Auditoria de exclusões críticas)
    """

    # 1. OWASP A01: RBAC - Apenas administradores podem remover usuários
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ação não permitida. Apenas administradores possuem este privilégio."
        )

    # 2. Prevenção de Auto-exclusão por esta rota
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível remover sua própria conta por este endpoint."
        )

    # 3. OWASP A01: Multitenancy Enforcement
    # A busca DEVE obrigatoriamente incluir o tenant_id do usuário autenticado
    target_user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == current_user.tenant_id
    ).first()

    if not target_user:
        # Retorna 404 para evitar vazamento de existência de IDs de outros tenants
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado."
        )

    # 4. Regra de Negócio: Impedir que o tenant fique sem administradores
    if target_user.role == UserRole.ADMIN:
        admin_count = db.query(User).filter(
            User.tenant_id == current_user.tenant_id,
            User.role == UserRole.ADMIN
        ).count()

        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Operação negada. A empresa deve possuir pelo menos um administrador ativo."
            )

    # 5. Remoção do Banco de Dados
    db.delete(target_user)
    db.commit()

    # 6. OWASP A09: Security Logging and Monitoring (Log estruturado sem dados sensíveis)
    print(
        f"[AUDIT LOG] Action: USER_HARD_DELETE | "
        f"ExecutorID: {current_user.id} | "
        f"TargetUserID: {user_id} | "
        f"TenantID: {current_user.tenant_id} | "
        f"Timestamp: {datetime.utcnow().isoformat()}"
    )

    return UserDeletionResponse(
        success=True,
        message="Usuário removido permanentemente com sucesso.",
        deleted_user_id=user_id,
        timestamp=datetime.utcnow()
    )