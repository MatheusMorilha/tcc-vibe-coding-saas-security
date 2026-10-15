"""
Alteração de permissões de usuários + trilha de auditoria (SaaS multilocatário).

Stack: FastAPI, SQLAlchemy 2.0, PostgreSQL (JSONB, SELECT ... FOR UPDATE), PyJWT.
Variáveis de ambiente: DATABASE_URL, JWT_SECRET.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Iterator

import jwt
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import (
    DDL,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Uuid,
    create_engine,
    event,
    func,
    select,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

# --------------------------------------------------------------------------- #
# Infra
# --------------------------------------------------------------------------- #
engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
JWT_SECRET = os.environ["JWT_SECRET"]


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Domínio: permissões e planos
# --------------------------------------------------------------------------- #
class Permission(str, Enum):
    USERS_MANAGE_PERMISSIONS = "users:manage_permissions"
    AUDIT_READ = "audit:read"
    REPORTS_READ = "reports:read"
    REPORTS_EXPORT = "reports:export"
    FINANCE_READ = "finance:read"
    FINANCE_WRITE = "finance:write"
    BILLING_MANAGE = "billing:manage"


_P = Permission
_STARTER = {_P.USERS_MANAGE_PERMISSIONS, _P.REPORTS_READ, _P.FINANCE_READ}
_PRO = _STARTER | {_P.REPORTS_EXPORT, _P.FINANCE_WRITE, _P.AUDIT_READ}
PLAN_ALLOWED: dict[str, set[str]] = {
    "starter": {p.value for p in _STARTER},
    "pro": {p.value for p in _PRO},
    "enterprise": {p.value for p in Permission},
}
ACTIVE_SUBSCRIPTION_STATES = {"active", "trialing"}


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class Company(Base):
    __tablename__ = "companies"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200))


class Subscription(Base):
    __tablename__ = "subscriptions"
    company_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("companies.id"), primary_key=True
    )
    plan: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(30))


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("companies.id"), index=True
    )
    email: Mapped[str] = mapped_column(String(320))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    permissions: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # Incrementado a cada mudança; permite invalidar sessões/caches de permissão.
    permissions_version: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AuditLog(Base):
    """
    Trilha append-only. Sem FK para users de propósito: o registro deve
    sobreviver à exclusão do usuário.
    """

    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    actor_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    target_user_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    before: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    after: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_audit_company_id_desc", "company_id", "id"),
        Index("ix_audit_company_target", "company_id", "target_user_id", "id"),
        Index("ix_audit_company_actor", "company_id", "actor_id", "id"),
    )


# Imutabilidade garantida no banco: UPDATE/DELETE na trilha são rejeitados.
# (Complemente com REVOKE UPDATE, DELETE, TRUNCATE para o role da aplicação.)
_fn = DDL(
    """
    CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION 'audit_log é append-only';
    END;
    $$ LANGUAGE plpgsql;
    """
)
_trg = DDL(
    """
    CREATE TRIGGER trg_audit_log_immutable
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
    """
)
event.listen(AuditLog.__table__, "after_create", _fn.execute_if(dialect="postgresql"))
event.listen(AuditLog.__table__, "after_create", _trg.execute_if(dialect="postgresql"))


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class PermissionUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rejeita campos inesperados

    permissions: list[Permission] = Field(max_length=len(Permission))
    reason: str = Field(min_length=5, max_length=500)

    @field_validator("reason")
    @classmethod
    def _strip_reason(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 5:
            raise ValueError("Informe uma justificativa com ao menos 5 caracteres.")
        return v


class PermissionChangeOut(BaseModel):
    user_id: uuid.UUID
    changed: bool
    permissions: list[str]
    added: list[str]
    removed: list[str]
    audit_id: int | None


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_id: uuid.UUID
    target_user_id: uuid.UUID
    action: str
    before: dict[str, Any]
    after: dict[str, Any]
    reason: str
    request_id: str
    ip_address: str | None
    user_agent: str | None
    created_at: datetime


class AuditPage(BaseModel):
    items: list[AuditLogOut]
    next_cursor: int | None


# --------------------------------------------------------------------------- #
# Autenticação: o tenant vem SEMPRE do token + banco, nunca do cliente
# --------------------------------------------------------------------------- #
def get_actor(request: Request, db: Session = Depends(get_db)) -> User:
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Não autenticado.")
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "sub", "cid"]},
        )
        user_id, company_id = uuid.UUID(claims["sub"]), uuid.UUID(claims["cid"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido.")

    # Permissões frescas do banco (não confiamos em claims para autorização).
    actor = db.scalar(
        select(User).where(
            User.id == user_id,
            User.company_id == company_id,
            User.is_active.is_(True),
        )
    )
    if actor is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuário inválido.")
    return actor


def _get_active_plan(db: Session, company_id: uuid.UUID) -> str:
    sub = db.scalar(select(Subscription).where(Subscription.company_id == company_id))
    if sub is None or sub.status not in ACTIVE_SUBSCRIPTION_STATES:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")
    return sub.plan


# --------------------------------------------------------------------------- #
# Rotas
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/api/v1", tags=["permissions"])


@router.put("/users/{user_id}/permissions", response_model=PermissionChangeOut)
def update_user_permissions(
    user_id: uuid.UUID,
    body: PermissionUpdateIn,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(get_actor),
) -> PermissionChangeOut:
    company_id = actor.company_id  # escopo de tenant derivado do ator autenticado
    plan = _get_active_plan(db, company_id)

    # Serializa alterações de permissão por empresa: evita corrida que deixaria
    # a empresa sem nenhum administrador e garante leitura consistente.
    db.execute(select(Company.id).where(Company.id == company_id).with_for_update())

    # Relê o ator já sob lock (suas permissões podem ter mudado há instantes).
    db.refresh(actor)
    if not actor.is_active or Permission.USERS_MANAGE_PERMISSIONS.value not in actor.permissions:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para esta ação.")

    if user_id == actor.id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Não é permitido alterar as próprias permissões.",
        )

    # Filtro por company_id: usuário de outra empresa é indistinguível de inexistente.
    target = db.scalar(
        select(User)
        .where(User.id == user_id, User.company_id == company_id)
        .with_for_update()
    )
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuário não encontrado.")

    before = sorted(set(target.permissions))
    after = sorted({p.value for p in body.permissions})
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))

    if not added and not removed:  # nada a fazer: sem escrita e sem ruído na trilha
        return PermissionChangeOut(
            user_id=target.id,
            changed=False,
            permissions=before,
            added=[],
            removed=[],
            audit_id=None,
        )

    # 1) Plano: só é possível conceder o que o plano contratado permite.
    not_in_plan = [p for p in added if p not in PLAN_ALLOWED.get(plan, set())]
    if not_in_plan:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Permissões não disponíveis no plano atual: {not_in_plan}",
        )

    # 2) Anti-escalonamento: o ator só mexe no que ele próprio possui.
    not_owned = [p for p in (*added, *removed) if p not in actor.permissions]
    if not_owned:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Você não pode conceder/revogar permissões que não possui: {not_owned}",
        )

    # 3) Anti-lockout: a empresa precisa manter ao menos um gestor de permissões.
    manage = Permission.USERS_MANAGE_PERMISSIONS.value
    if manage in removed:
        other_admins = db.scalar(
            select(func.count())
            .select_from(User)
            .where(
                User.company_id == company_id,
                User.is_active.is_(True),
                User.id != target.id,
                User.permissions.contains([manage]),
            )
        )
        if not other_admins:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "A empresa deve manter ao menos um usuário que gerencie permissões.",
            )

    # Alteração + auditoria na MESMA transação: ou ocorrem juntas ou nenhuma.
    target.permissions = after
    target.permissions_version += 1

    entry = AuditLog(
        company_id=company_id,
        actor_id=actor.id,
        target_user_id=target.id,
        action="user.permissions.updated",
        before={"permissions": before},
        after={"permissions": after},
        reason=body.reason,
        request_id=request.headers.get("X-Request-ID", "")[:64] or uuid.uuid4().hex,
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("User-Agent") or "")[:255] or None,
    )
    db.add(entry)
    db.commit()

    return PermissionChangeOut(
        user_id=target.id,
        changed=True,
        permissions=after,
        added=added,
        removed=removed,
        audit_id=entry.id,
    )


@router.get("/audit-logs", response_model=AuditPage)
def list_audit_logs(
    db: Session = Depends(get_db),
    actor: User = Depends(get_actor),
    target_user_id: uuid.UUID | None = None,
    actor_id: uuid.UUID | None = None,
    action: str | None = Query(None, max_length=64),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(50, ge=1, le=100),
    cursor: int | None = Query(None, ge=1, description="id do último item da página anterior"),
) -> AuditPage:
    _get_active_plan(db, actor.company_id)
    if Permission.AUDIT_READ.value not in actor.permissions:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para consultar a auditoria.")

    # O filtro de tenant é obrigatório e vem do ator, não de parâmetros.
    stmt = select(AuditLog).where(AuditLog.company_id == actor.company_id)
    if target_user_id:
        stmt = stmt.where(AuditLog.target_user_id == target_user_id)
    if actor_id:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if since:
        stmt = stmt.where(AuditLog.created_at >= since)
    if until:
        stmt = stmt.where(AuditLog.created_at < until)
    if cursor:
        stmt = stmt.where(AuditLog.id < cursor)

    rows = list(db.scalars(stmt.order_by(AuditLog.id.desc()).limit(limit + 1)))
    has_more = len(rows) > limit
    rows = rows[:limit]
    return AuditPage(
        items=[AuditLogOut.model_validate(r) for r in rows],
        next_cursor=rows[-1].id if has_more and rows else None,
    )


app = FastAPI(title="Plataforma SaaS - Permissões e Auditoria")
app.include_router(router)