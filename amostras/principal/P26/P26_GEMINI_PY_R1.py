from datetime import datetime
from uuid import UUID, uuid4
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id = Column(PG_UUID(as_uuid=True), nullable=False, index=True)
    email = Column(String, nullable=False)
    role = Column(String, nullable=False)  # ex: "admin", "member"
    permissions = Column(JSON, nullable=False, default=list)  # ex: ["read:reports", "write:orders"]

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id = Column(PG_UUID(as_uuid=True), nullable=False, index=True)
    actor_id = Column(PG_UUID(as_uuid=True), nullable=False)      # Quem realizou a ação
    target_user_id = Column(PG_UUID(as_uuid=True), nullable=False) # Usuário afetado
    action = Column(String, nullable=False)                       # "UPDATE_PERMISSIONS"
    details = Column(JSON, nullable=False)                        # Dados do diff
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

from typing import List
from pydantic import BaseModel, Field
from uuid import UUID

class UpdatePermissionsRequest(BaseModel):
    permissions: List[str] = Field(
        ...,
        description="Lista completa das novas permissões do usuário",
        example=["read:reports", "write:orders", "delete:clients"]
    )

class UserPermissionsResponse(BaseModel):
    user_id: UUID
    tenant_id: UUID
    permissions: List[str]
    message: str

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from uuid import UUID

# Importações fictícias das dependências do sistema
from database import get_db
from auth import get_current_user, UserContext

router = APIRouter(prefix="/v1/users", tags=["Gestão de Usuários"])

@router.patch(
    "/{target_user_id}/permissions",
    response_model=UserPermissionsResponse,
    status_code=status.HTTP_200_OK,
    summary="Atualiza permissões de um usuário e gera log de auditoria")
async def update_user_permissions(
    target_user_id: UUID,
    payload: UpdatePermissionsRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: UserContext = Depends(get_current_user)):
    """
    Altera as permissões de um usuário pertencente ao mesmo tenant do administrador logado.
    Gera obrigatoriamente um registro na trilha de auditoria.
    """
    # 1. Validação de Autorização (Somente admins do mesmo tenant)
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas administradores podem alterar permissões de usuários."
        )

    # 2. Busca o usuário garantindo o isolamento multi-tenant (tenant_id do usuário logado)
    query = select(User).where(
        User.id == target_user_id,
        User.tenant_id == current_user.tenant_id
    )
    result = await db.execute(query)
    target_user = result.scalars().first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado nesta organização."
        )

    # 3. Preserva o estado anterior para a trilha de auditoria
    previous_permissions = list(target_user.permissions or [])
    new_permissions = payload.permissions

    # Se as permissões forem idênticas, não processa alteração nem log
    if set(previous_permissions) == set(new_permissions):
        return UserPermissionsResponse(
            user_id=target_user.id,
            tenant_id=target_user.tenant_id,
            permissions=target_user.permissions,
            message="Nenhuma alteração detectada."
        )

    # 4. Atualiza as permissões do usuário
    target_user.permissions = new_permissions

    # 5. Registra o evento de auditoria
    client_ip = request.client.host if request.client else None

    audit_entry = AuditLog(
        tenant_id=current_user.tenant_id,
        actor_id=current_user.id,
        target_user_id=target_user.id,
        action="USER_PERMISSIONS_UPDATED",
        details={
            "previous_permissions": previous_permissions,
            "new_permissions": new_permissions,
            "added_permissions": list(set(new_permissions) - set(previous_permissions)),
            "removed_permissions": list(set(previous_permissions) - set(new_permissions))
        },
        ip_address=client_ip
    )

    db.add(audit_entry)

    # 6. Persiste as alterações atomicamente (Transação ACID)
    try:
        await db.commit()
        await db.refresh(target_user)
    except Exception as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao atualizar permissões e gravar auditoria."
        ) from exc

    return UserPermissionsResponse(
        user_id=target_user.id,
        tenant_id=target_user.tenant_id,
        permissions=target_user.permissions,
        message="Permissões atualizadas com sucesso."
    )