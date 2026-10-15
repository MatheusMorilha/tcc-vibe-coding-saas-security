from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, Enum as SQLEnum, ForeignKey, String, Table, create_engine
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session, sessionmaker

# ------------------------------------------------------------------------------
# 1. MODELOS DE DADOS (SQLAlchemy)
# ------------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass

class PermissionEnum(str, Enum):
    READ_REPORTS = "read:reports"
    WRITE_REPORTS = "write:reports"
    MANAGE_USERS = "manage:users"
    MANAGE_FINANCIAL = "manage:financial"

class UserPermission(Base):
    """Tabela de associação de permissões de usuários."""
    __tablename__ = "user_permissions"

    user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), primary_key=True)
    permission: Mapped[PermissionEnum] = mapped_column(SQLEnum(PermissionEnum), primary_key=True)

class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="MEMBER")

    # Relacionamento de permissões do usuário
    permissions: Mapped[List[UserPermission]] = relationship("UserPermission", cascade="all, delete-orphan")

class AuditLog(Base):
    """Tabela append-only para trilha de auditoria."""
    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), index=True, nullable=False)
    actor_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)  # Quem fez a ação
    target_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False) # Usuário alterado
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False)                   # Payload antes/depois
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

# ------------------------------------------------------------------------------
# 2. SCHEMAS PYDANTIC (DTOs)
# ------------------------------------------------------------------------------

class UpdatePermissionsSchema(BaseModel):
    permissions: List[PermissionEnum] = Field(
        ..., description="Lista completa das novas permissões a serem atribuídas ao usuário."
    )

class UserPermissionsResponse(BaseModel):
    user_id: UUID
    tenant_id: UUID
    permissions: List[PermissionEnum]
    updated_at: datetime

class AuthenticatedUser(BaseModel):
    """Contexto do usuário extraído do Token JWT."""
    id: UUID
    tenant_id: UUID
    role: str

# ------------------------------------------------------------------------------
# 3. DEPENDÊNCIAS DE INJEÇÃO
# ------------------------------------------------------------------------------

def get_db():
    """Gerenciador de sessão do banco de dados (mock/placeholder para injeção)."""
    db = Session()
    try:
        yield db
    finally:
        db.close()

def get_current_user() -> AuthenticatedUser:
    """
    Mock de middleware de autenticação.
    Em produção, valida o Token JWT do cabeçalho Authorization e retorna
    o ID do usuário e o Tenant ID associado.
    """
    return AuthenticatedUser(
        id=UUID("00000000-0000-0000-0000-000000000001"),
        tenant_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        role="ADMIN"
    )

# ------------------------------------------------------------------------------
# 4. ROTA DA API (FastAPI Router)
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/users", tags=["Gestão de Usuários"])

@router.put(
    "/{target_user_id}/permissions",
    response_model=UserPermissionsResponse,
    status_code=status.HTTP_200_OK,
    summary="Atualiza as permissões de um usuário e gera log de auditoria")
def update_user_permissions(
    target_user_id: UUID,
    payload: UpdatePermissionsSchema,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user)):
    # 1. Validação de Autorização (Somente admins ou gestores podem alterar permissões)
    if current_user.role not in ["ADMIN", "OWNER"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas administradores podem gerenciar permissões de usuários."
        )

    # 2. Busca o usuário garantindo ISOLAMENTO MULTITENANT
    target_user = db.query(User).filter(
        User.id == target_user_id,
        User.tenant_id == current_user.tenant_id  # Restrição estrita de tenant
    ).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado na organização corrente."
        )

    # 3. Captura o estado anterior para a auditoria
    previous_permissions = [p.permission.value for p in target_user.permissions]
    new_permissions = [p.value for p in set(payload.permissions)]

    # Se não houver mudanças reais, encerra sem gravar auditoria desnecessária
    if set(previous_permissions) == set(new_permissions):
        return UserPermissionsResponse(
            user_id=target_user.id,
            tenant_id=target_user.tenant_id,
            permissions=[PermissionEnum(p) for p in previous_permissions],
            updated_at=datetime.now(timezone.utc)
        )

    try:
        # 4. Atualiza as permissões dentro de uma transação atômica
        target_user.permissions.clear()
        for perm in set(payload.permissions):
            target_user.permissions.append(UserPermission(permission=perm))

        # 5. Registra a Trilha de Auditoria (Audit Log)
        audit_entry = AuditLog(
            tenant_id=current_user.tenant_id,
            actor_id=current_user.id,
            target_id=target_user.id,
            action="USER_PERMISSIONS_UPDATED",
            details={
                "previous_permissions": previous_permissions,
                "new_permissions": new_permissions,
                "granted": list(set(new_permissions) - set(previous_permissions)),
                "revoked": list(set(previous_permissions) - set(new_permissions))
            }
        )
        db.add(audit_entry)

        # Persiste todas as mudanças atomicamente
        db.commit()
        db.refresh(target_user)

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao processar a atualização de permissões."
        ) from exc

    return UserPermissionsResponse(
        user_id=target_user.id,
        tenant_id=target_user.tenant_id,
        permissions=[p.permission for p in target_user.permissions],
        updated_at=audit_entry.created_at
    )