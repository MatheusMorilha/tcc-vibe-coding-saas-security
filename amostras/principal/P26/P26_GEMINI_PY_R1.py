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