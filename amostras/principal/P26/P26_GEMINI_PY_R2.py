import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, DateTime, ForeignKey, select
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import declarative_base, relationship

# ------------------------------------------------------------------------------
# 1. MODELS (SQLAlchemy)
# ------------------------------------------------------------------------------
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    permissions = Column(JSONB, nullable=False, default=list)  # Ex: ["user:read", "invoice:create"]

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    actor_id = Column(UUID(as_uuid=True), nullable=False)  # Quem fez a alteração
    target_id = Column(UUID(as_uuid=True), nullable=False) # Quem sofreu a alteração
    action = Column(String(100), nullable=False)          # Ex: "USER_PERMISSIONS_UPDATE"
    details = Column(JSONB, nullable=False)               # Estado anterior e novo estado
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


# ------------------------------------------------------------------------------
# 2. SCHEMAS (Pydantic)
# ------------------------------------------------------------------------------
class UpdatePermissionsSchema(BaseModel):
    permissions: List[str] = Field(
        ...,
        description="Lista completa das novas permissões atribuídas ao usuário",
        example=["sales:read", "sales:write", "reports:export"]
    )

class UserResponseSchema(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    permissions: List[str]

    class Config:
        from_attributes = True


# ------------------------------------------------------------------------------
# 3. DEPENDÊNCIES E MOCKS DE SESSÃO/AUTENTICAÇÃO
# ------------------------------------------------------------------------------
class CurrentUser(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    permissions: List[str]

async def get_db_session() -> AsyncSession:
    """Injeta a sessão assíncrona do banco de dados (exemplo)."""
    raise NotImplementedError("Substitua pelo seu session generator do SQLAlchemy")

async def get_current_user() -> CurrentUser:
    """
    Injeta o usuário logado extraído do JWT Token.
    Valida a assinatura do plano da empresa antes de permitir mutações.
    """
    # Exemplo mockado do usuário logado (Admin da empresa)
    return CurrentUser(
        id=uuid.UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"),
        tenant_id=uuid.UUID("b71e8c72-2f3a-4a2e-9d2a-1b2c3d4e5f6a"),
        permissions=["admin", "users:manage"]
    )


# ------------------------------------------------------------------------------
# 4. ROTA DA API
# ------------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/users", tags=["Users"])

@router.put(
    "/{user_id}/permissions",
    response_model=UserResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Atualiza permissões de um usuário e gera log de auditoria")
async def update_user_permissions(
    user_id: uuid.UUID,
    payload: UpdatePermissionsSchema,
    session: AsyncSession = Depends(get_db_session),
    actor: CurrentUser = Depends(get_current_user)):
    # Authorization logic (Role-Based Access Control)
    if "users:manage" not in actor.permissions and "admin" not in actor.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ação não permitida para as credenciais fornecidas."
        )

    # 1. Busca o usuário garantindo o isolamento Multi-Tenant
    query = select(User).where(
        User.id == user_id,
        User.tenant_id == actor.tenant_id  # <--- Essencial para segurança SaaS
    )
    result = await session.execute(query)
    target_user = result.scalar_one_or_none()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado na organização atual."
        )

    # 2. Captura o estado anterior para a Trilha de Auditoria
    old_permissions = list(target_user.permissions or [])
    new_permissions = payload.permissions

    # Se não houve alteração real, evita registrar log desnecessário
    if old_permissions == new_permissions:
        return target_user

    # 3. Atualiza as permissões do usuário
    target_user.permissions = new_permissions

    # 4. Registra o Log de Auditoria na mesma transação
    audit_entry = AuditLog(
        tenant_id=actor.tenant_id,
        actor_id=actor.id,
        target_id=target_user.id,
        action="USER_PERMISSIONS_UPDATE",
        details={
            "before": old_permissions,
            "after": new_permissions,
            "changed_at": datetime.now(timezone.utc).isoformat()
        }
    )

    session.add(audit_entry)

    # 5. Commit atômico (Garante que a mudança e o audit log persistam juntos)
    try:
        await session.commit()
        await session.refresh(target_user)
    except Exception as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao processar a atualização de permissões."
        ) from exc

    return target_user