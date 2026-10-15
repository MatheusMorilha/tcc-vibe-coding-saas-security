"""
Alteração de permissões de usuário + trilha de auditoria (SaaS multilocatário).

Stack: FastAPI, SQLAlchemy 2.0, PostgreSQL, PyJWT.

Princípios de segurança aplicados:
  1. O tenant vem SEMPRE do token autenticado, nunca do corpo/URL da requisição.
  2. Toda query filtra por tenant_id (usuário de outro tenant => 404, sem vazar existência).
  3. As permissões do ator são lidas do banco (não do token), então revogações valem na hora.
  4. Alteração + registro de auditoria acontecem na MESMA transação (ou ambos ou nenhum).
  5. A trilha de auditoria é append-only, garantida por trigger no banco.
  6. Anti-escalonamento de privilégio: ninguém concede/revoga o que não possui.
  7. Proteção contra auto-alteração e contra remover o último administrador.
  8. Controle de concorrência otimista (expected_version) + lock por tenant.
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterator

import jwt
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import (
    BigInteger, Boolean, DateTime, ForeignKey, Identity, Index, Integer, String,
    create_engine, func, select, text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
DATABASE_URL = os.environ["DATABASE_URL"]          # ex.: postgresql+psycopg://...
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)

# --------------------------------------------------------------------------- #
# Catálogo de permissões e regras por plano
# --------------------------------------------------------------------------- #
P_ADMIN = "tenant:admin"
P_MANAGE_PERMS = "users:manage_permissions"
P_AUDIT_READ = "audit:read"

PLAN_PERMISSIONS: dict[str, frozenset[str]] = {
    "basic": frozenset({"invoices:read", "invoices:write", "customers:read", "customers:write"}),
}
PLAN_PERMISSIONS["pro"] = PLAN_PERMISSIONS["basic"] | {"reports:read", "reports:export"}
PLAN_PERMISSIONS["enterprise"] = PLAN_PERMISSIONS["pro"] | {
    P_ADMIN, P_MANAGE_PERMS, P_AUDIT_READ, "sso:configure",
}
# Permissões administrativas estão disponíveis em todos os planos para o admin
# do tenant, mas "audit:read" e "sso:configure" dependem do plano enterprise.
_ALWAYS_AVAILABLE = frozenset({P_ADMIN, P_MANAGE_PERMS})
ALL_PERMISSIONS = frozenset().union(*PLAN_PERMISSIONS.values()) | _ALWAYS_AVAILABLE


def allowed_for_plan(plan: str) -> frozenset[str]:
    return PLAN_PERMISSIONS.get(plan, frozenset()) | _ALWAYS_AVAILABLE


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200))
    plan: Mapped[str] = mapped_column(String(32), default="basic")
    subscription_active: Mapped[bool] = mapped_column(Boolean, default=True)


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(320))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    permissions: Mapped[list[str]] = mapped_column(JSONB, default=list)
    version: Mapped[int] = mapped_column(Integer, default=1)   # concorrência otimista

    __table_args__ = (Index("ux_users_tenant_email", "tenant_id", "email", unique=True),)


class AuditLog(Base):
    """Trilha de auditoria append-only (UPDATE/DELETE bloqueados por trigger)."""
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    actor_user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    target_user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    action: Mapped[str] = mapped_column(String(64))             # ex.: user.permissions.updated
    before: Mapped[dict[str, Any]] = mapped_column(JSONB)
    after: Mapped[dict[str, Any]] = mapped_column(JSONB)
    added: Mapped[list[str]] = mapped_column(JSONB)
    removed: Mapped[list[str]] = mapped_column(JSONB)
    reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(300), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    __table_args__ = (
        Index("ix_audit_tenant_id_desc", "tenant_id", "id"),
        Index("ix_audit_tenant_target", "tenant_id", "target_user_id", "id"),
        Index("ix_audit_tenant_actor", "tenant_id", "actor_user_id", "id"),
    )


AUDIT_GUARD_SQL = """
CREATE OR REPLACE FUNCTION audit_logs_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs é append-only: % não permitido', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;
CREATE TRIGGER trg_audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();

DROP TRIGGER IF EXISTS trg_audit_logs_no_truncate ON audit_logs;
CREATE TRIGGER trg_audit_logs_no_truncate
    BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_immutable();
"""


def install_audit_guards() -> None:
    """Chamar em migração/boot. Em produção, também revogue UPDATE/DELETE do
    papel da aplicação e considere Row-Level Security por tenant_id."""
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text(AUDIT_GUARD_SQL))


# --------------------------------------------------------------------------- #
# Dependências: sessão e autenticação
# --------------------------------------------------------------------------- #
def get_db() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session


@dataclass(frozen=True)
class AuthContext:
    user_id: uuid.UUID
    tenant_id: uuid.UUID


def get_auth(authorization: str = Header(default="")) -> AuthContext:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciais ausentes.")
    try:
        claims = jwt.decode(
            token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "sub", "tenant_id"]},
        )
        return AuthContext(uuid.UUID(claims["sub"]), uuid.UUID(claims["tenant_id"]))
    except (jwt.PyJWTError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido ou expirado.")


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class PermissionsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    permissions: list[str] = Field(max_length=100, description="Conjunto final de permissões.")
    expected_version: int = Field(ge=1, description="Versão do usuário lida pelo cliente.")
    reason: str | None = Field(default=None, max_length=500)

    @field_validator("permissions")
    @classmethod
    def _normalize(cls, v: list[str]) -> list[str]:
        return sorted({p.strip() for p in v if p.strip()})


class PermissionsOut(BaseModel):
    user_id: uuid.UUID
    permissions: list[str]
    version: int
    changed: bool
    audit_id: int | None


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    occurred_at: datetime
    actor_user_id: uuid.UUID
    target_user_id: uuid.UUID
    action: str
    before: dict[str, Any]
    after: dict[str, Any]
    added: list[str]
    removed: list[str]
    reason: str | None
    ip_address: str | None
    request_id: str | None


class AuditPage(BaseModel):
    items: list[AuditOut]
    next_cursor: int | None


# --------------------------------------------------------------------------- #
# Rotas
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/api/v1", tags=["permissions"])


def _client_ip(request: Request) -> str | None:
    # Ajuste conforme seu proxy reverso (use apenas headers de proxies confiáveis).
    return request.client.host if request.client else None


@router.put("/users/{user_id}/permissions", response_model=PermissionsOut)
def update_user_permissions(
    user_id: uuid.UUID,
    body: PermissionsIn,
    request: Request,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> PermissionsOut:
    try:
        # Lock do tenant: serializa mudanças de permissão dentro da mesma empresa,
        # evitando corrida na regra do "último administrador".
        tenant = db.scalar(
            select(Tenant).where(Tenant.id == auth.tenant_id).with_for_update()
        )
        if tenant is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Tenant inválido.")
        if not tenant.subscription_active:
            raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa.")

        # Ator: permissões lidas do banco, não do token.
        actor = db.scalar(
            select(User).where(
                User.id == auth.user_id,
                User.tenant_id == auth.tenant_id,
                User.is_active.is_(True),
            )
        )
        if actor is None or P_MANAGE_PERMS not in actor.permissions:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para gerenciar acessos.")

        if user_id == actor.id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Não é permitido alterar as próprias permissões.")

        # Alvo restrito ao tenant do ator (outro tenant => 404, sem vazar existência).
        target = db.scalar(
            select(User)
            .where(User.id == user_id, User.tenant_id == auth.tenant_id)
            .with_for_update()
        )
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuário não encontrado.")

        if target.version != body.expected_version:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "O usuário foi modificado por outra operação. Recarregue e tente novamente.",
            )

        new_perms = set(body.permissions)
        old_perms = set(target.permissions)

        unknown = new_perms - ALL_PERMISSIONS
        if unknown:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Permissões desconhecidas: {sorted(unknown)}",
            )

        added, removed = new_perms - old_perms, old_perms - new_perms

        # Só valida plano para o que está sendo CONCEDIDO (revogar é sempre possível).
        not_in_plan = added - allowed_for_plan(tenant.plan)
        if not_in_plan:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Permissões indisponíveis no plano '{tenant.plan}': {sorted(not_in_plan)}",
            )

        # Anti-escalonamento: só concede/revoga o que o próprio ator possui.
        if (added | removed) - set(actor.permissions):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Não é permitido conceder ou revogar permissões que você não possui.",
            )

        # Idempotência: nada mudou => não polui a trilha nem incrementa a versão.
        if not added and not removed:
            return PermissionsOut(
                user_id=target.id, permissions=sorted(old_perms),
                version=target.version, changed=False, audit_id=None,
            )

        # Nunca deixar o tenant sem administrador ativo.
        if P_ADMIN in removed and target.is_active:
            other_admins = db.scalar(
                select(func.count()).select_from(User).where(
                    User.tenant_id == auth.tenant_id,
                    User.id != target.id,
                    User.is_active.is_(True),
                    User.permissions.contains([P_ADMIN]),
                )
            )
            if not other_admins:
                raise HTTPException(
                    status.HTTP_409_CONFLICT, "O tenant precisa manter ao menos um administrador ativo."
                )

        before = {"permissions": sorted(old_perms), "version": target.version}
        target.permissions = sorted(new_perms)
        target.version += 1
        after = {"permissions": sorted(new_perms), "version": target.version}

        entry = AuditLog(
            tenant_id=auth.tenant_id,
            actor_user_id=actor.id,
            target_user_id=target.id,
            action="user.permissions.updated",
            before=before,
            after=after,
            added=sorted(added),
            removed=sorted(removed),
            reason=body.reason,
            ip_address=_client_ip(request),
            user_agent=(request.headers.get("user-agent") or "")[:300] or None,
            request_id=request.headers.get("x-request-id"),
        )
        db.add(entry)
        db.flush()               # obtém entry.id
        audit_id = entry.id
        db.commit()              # alteração + auditoria: atômicos

        return PermissionsOut(
            user_id=target.id, permissions=sorted(new_perms),
            version=target.version, changed=True, audit_id=audit_id,
        )
    except Exception:
        db.rollback()
        raise


@router.get("/audit-logs", response_model=AuditPage, tags=["audit"])
def list_audit_logs(
    target_user_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    action: str | None = Query(default=None, max_length=64),
    since: datetime | None = None,
    until: datetime | None = None,
    cursor: int | None = Query(default=None, ge=1, description="Retorna registros com id menor que o cursor."),
    limit: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> AuditPage:
    reader = db.scalar(
        select(User).where(
            User.id == auth.user_id,
            User.tenant_id == auth.tenant_id,
            User.is_active.is_(True),
        )
    )
    if reader is None or not ({P_AUDIT_READ, P_ADMIN} & set(reader.permissions)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para consultar a auditoria.")

    # O filtro por tenant é obrigatório e vem do token, nunca de parâmetro.
    stmt = select(AuditLog).where(AuditLog.tenant_id == auth.tenant_id)
    if target_user_id:
        stmt = stmt.where(AuditLog.target_user_id == target_user_id)
    if actor_user_id:
        stmt = stmt.where(AuditLog.actor_user_id == actor_user_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if since:
        stmt = stmt.where(AuditLog.occurred_at >= since.astimezone(timezone.utc))
    if until:
        stmt = stmt.where(AuditLog.occurred_at <= until.astimezone(timezone.utc))
    if cursor:
        stmt = stmt.where(AuditLog.id < cursor)

    rows = list(db.scalars(stmt.order_by(AuditLog.id.desc()).limit(limit + 1)))
    has_more = len(rows) > limit
    rows = rows[:limit]
    return AuditPage(
        items=[AuditOut.model_validate(r) for r in rows],
        next_cursor=rows[-1].id if has_more and rows else None,
    )


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
app = FastAPI(title="SaaS Gestão Empresarial")
app.include_router(router)

if __name__ == "__main__":
    install_audit_guards()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)