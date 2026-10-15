from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import (
    Column, DateTime, ForeignKey, Integer, JSON, String, create_engine
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

app = FastAPI()

DATABASE_URL = "sqlite:///./saas.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, nullable=False, index=True)
    permissions = Column(JSON, nullable=False, default=list)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True)
    tenant_id = Column(Integer, nullable=False, index=True)
    actor_user_id = Column(Integer, nullable=False)
    target_user_id = Column(Integer, nullable=False)
    action = Column(String, nullable=False)
    before = Column(JSON, nullable=False)
    after = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)


Base.metadata.create_all(engine)


class PermissionUpdate(BaseModel):
    permissions: list[str] = Field(default_factory=list)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user() -> User:
    # Substituir por autenticação real (JWT/OAuth2).
    return User(id=1, tenant_id=10)


@app.put("/users/{user_id}/permissions")
def update_permissions(
    user_id: int,
    payload: PermissionUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # O tenant_id vem do usuário autenticado, nunca do request.
    user = (
        db.query(User)
        .filter(
            User.id == user_id,
            User.tenant_id == current_user.tenant_id,
        )
        .with_for_update()
        .first()
    )

    if user is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    before = list(user.permissions or [])
    after = sorted(set(payload.permissions))

    user.permissions = after

    audit = AuditLog(
        id=str(uuid4()),
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        target_user_id=user.id,
        action="user.permissions.updated",
        before=before,
        after=after,
        created_at=datetime.now(timezone.utc),
    )

    # Permissão e auditoria são persistidas atomicamente.
    db.add(audit)
    db.commit()

    return {
        "user_id": user.id,
        "permissions": after,
        "audit_id": audit.id,
    }


@app.get("/users/{user_id}/permission-audit")
def get_permission_audit(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Também restringe a consulta ao tenant autenticado.
    logs = (
        db.query(AuditLog)
        .filter(
            AuditLog.target_user_id == user_id,
            AuditLog.tenant_id == current_user.tenant_id,
            AuditLog.action == "user.permissions.updated",
        )
        .order_by(AuditLog.created_at.desc())
        .all()
    )

    return [
        {
            "audit_id": log.id,
            "actor_user_id": log.actor_user_id,
            "before": log.before,
            "after": log.after,
            "created_at": log.created_at,
        }
        for log in logs
    ]
