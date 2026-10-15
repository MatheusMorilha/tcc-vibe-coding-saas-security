"""
Alteração de permissões de usuário + trilha de auditoria (SaaS multilocatário).

Dependências: fastapi, uvicorn, sqlalchemy>=2.0, pydantic>=2, psycopg[binary]
Banco recomendado: PostgreSQL (SELECT ... FOR UPDATE e timestamptz).

Decisões de segurança:
  * O tenant (company_id) vem SEMPRE do usuário autenticado, nunca do corpo/URL.
  * Usuário de outra empresa é indistinguível de inexistente (404), sem vazar existência.
  * Anti-escalada de privilégio: só é possível conceder/revogar permissões que o
    próprio ator possui (owner tem todas).
  * Ator não altera as próprias permissões; permissões de 'owner' são imutáveis aqui.
  * Alteração + auditoria na MESMA transação (ou grava os dois, ou nenhum).
  * Auditoria append-only (UPDATE/DELETE bloqueados na camada ORM) e encadeada por
    hash por tenant, permitindo detectar adulteração posterior.
  * Lock na linha da empresa serializa mudanças do tenant e mantém a cadeia de hash íntegra.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Iterator, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, create_engine, event, select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

# --------------------------------------------------------------------------- #
# Infra
# --------------------------------------------------------------------------- #
DATABASE_URL = "postgresql+psycopg://user:pass@localhost:5432/saas"
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Domínio
# --------------------------------------------------------------------------- #
class Role(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


class Permission(str, Enum):
    USERS_READ = "users:read"
    USERS_MANAGE_PERMISSIONS = "users:manage_permissions"
    BILLING_MANAGE = "billing:manage"
    REPORTS_VIEW = "reports:view"
    AUDIT_READ = "audit:read"


ALL_PERMISSIONS = frozenset(p.value for p in Permission)
FEATURE_GRANULAR_PERMISSIONS = "granular_permissions"


class Company(Base):
    __tablename__ = "companies"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200))
    subscription_status: Mapped[str] = mapped_column(String(20), default="active")
    plan_features: Mapped[list] = mapped_column(JSON, default=list)


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("companies.id"), index=True)
    email: Mapped[str] = mapped_column(String(320))
    role: Mapped[str] = mapped_column(String(20), default=Role.MEMBER.value)
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    permissions_version: Mapped[int] = mapped_column(Integer, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class AuditLog(Base):
    """Trilha de auditoria append-only, encadeada por hash dentro de cada tenant."""
    __tablename__ = "audit_logs"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[uuid.UUID] = mapped_column(unique=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("companies.id"))
    actor_user_id: Mapped[uuid.UUID] = mapped_column()
    target_user_id: Mapped[uuid.UUID] = mapped_column()
    action: Mapped[str] = mapped_column(String(60))
    before: Mapped[list] = mapped_column(JSON)
    after: Mapped[list] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(String(500))
    request_id: Mapped[str] = mapped_column(String(64))
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    prev_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    hash: Mapped[str] = mapped_column(String(64))

    __table_args__ = (
        Index("ix_audit_company_seq", "company_id", "seq"),
        Index("ix_audit_company_target", "company_id", "target_user_id", "seq"),
        Index("ix_audit_company_actor", "company_id", "actor_user_id", "seq"),
    )


@event.listens_for(AuditLog, "before_update")
def _audit_no_update(*_args):
    raise RuntimeError("audit_logs é append-only: UPDATE proibido")


@event.listens_for(AuditLog, "before_delete")
def _audit_no_delete(*_args):
    raise RuntimeError("audit_logs é append-only: DELETE proibido")


# Complemento recomendado em produção: o usuário de banco da aplicação deve ter
# apenas INSERT/SELECT em audit_logs (REVOKE UPDATE, DELETE, TRUNCATE).


def compute_hash(prev_hash: Optional[str], e: AuditLog) -> str:
    payload = json.dumps(
        {
            "event_id": str(e.event_id),
            "company_id": str(e.company_id),
            "actor": str(e.actor_user_id),
            "target": str(e.target_user_id),
            "action": e.action,
            "before": e.before,
            "after": e.after,
            "reason": e.reason,
            "request_id": e.request_id,
            "ip": e.ip_address,
            "ts": e.created_at.astimezone(timezone.utc).isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(((prev_hash or "") + payload).encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Dependências (sessão e autenticação)
# --------------------------------------------------------------------------- #
def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def decode_access_token(token: str) -> uuid.UUID:
    """Substituir pela validação real do JWT (assinatura, exp, aud, iss).
    Deve retornar o 'sub' (id do usuário). Nunca confiar em company_id vindo do token
    sem rechecar no banco."""
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido")


def get_current_user(
    authorization: str = Header(...),
    db: Session = Depends(get_db),
) -> User:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciais ausentes")
    user = db.get(User, decode_access_token(token))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuário inválido")
    return user


def effective_permissions(user: User) -> frozenset[str]:
    if user.role == Role.OWNER.value:
        return ALL_PERMISSIONS
    return frozenset(user.permissions or [])


def require_permission(user: User, perm: Permission) -> None:
    if perm.value not in effective_permissions(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permissão insuficiente")


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class PermissionUpdateIn(BaseModel):
    permissions: list[Permission] = Field(..., description="Conjunto final de permissões")
    reason: str = Field(..., min_length=5, max_length=500, description="Justificativa")
    expected_version: Optional[int] = Field(
        None, description="Controle otimista: versão de permissões que o cliente viu"
    )


class PermissionUpdateOut(BaseModel):
    user_id: uuid.UUID
    changed: bool
    permissions: list[str]
    permissions_version: int
    added: list[str]
    removed: list[str]
    audit_event_id: Optional[uuid.UUID]


class AuditLogOut(BaseModel):
    seq: int
    event_id: uuid.UUID
    actor_user_id: uuid.UUID
    target_user_id: uuid.UUID
    action: str
    before: list[str]
    after: list[str]
    reason: str
    request_id: str
    ip_address: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditPageOut(BaseModel):
    items: list[AuditLogOut]
    next_cursor: Optional[int]


# --------------------------------------------------------------------------- #
# Rotas
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/api/v1")


def _append_audit(db: Session, *, request: Request, actor: User, target: User,
                  before: list[str], after: list[str], reason: str) -> AuditLog:
    last_hash = db.execute(
        select(AuditLog.hash)
        .where(AuditLog.company_id == actor.company_id)
        .order_by(AuditLog.seq.desc())
        .limit(1)
    ).scalar_one_or_none()

    entry = AuditLog(
        event_id=uuid.uuid4(),
        company_id=actor.company_id,
        actor_user_id=actor.id,
        target_user_id=target.id,
        action="user.permissions.updated",
        before=before,
        after=after,
        reason=reason.strip(),
        request_id=request.headers.get("x-request-id", str(uuid.uuid4()))[:64],
        # Atrás de proxy/LB, usar o IP confiável (ex.: ProxyHeadersMiddleware).
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:255] or None,
        created_at=utcnow(),
        prev_hash=last_hash,
        hash="",
    )
    entry.hash = compute_hash(last_hash, entry)
    db.add(entry)
    return entry


@router.put("/users/{user_id}/permissions", response_model=PermissionUpdateOut)
def update_user_permissions(
    user_id: uuid.UUID,
    body: PermissionUpdateIn,
    request: Request,
    actor: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # 1) Autorização do ator
    require_permission(actor, Permission.USERS_MANAGE_PERMISSIONS)
    if user_id == actor.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Não é permitido alterar as próprias permissões")

    # 2) Serializa mudanças do tenant (mantém a cadeia de auditoria consistente)
    company = db.execute(
        select(Company).where(Company.id == actor.company_id).with_for_update()
    ).scalar_one()

    # 3) Assinatura ativa e plano com o recurso
    if company.subscription_status != "active":
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "Assinatura inativa")
    if FEATURE_GRANULAR_PERMISSIONS not in (company.plan_features or []):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "O plano atual não inclui permissões granulares")

    # 4) Carrega o alvo SEMPRE filtrando pelo tenant do ator
    target = db.execute(
        select(User)
        .where(User.id == user_id, User.company_id == actor.company_id)
        .with_for_update()
    ).scalar_one_or_none()
    if target is None or not target.is_active:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuário não encontrado")
    if target.role == Role.OWNER.value:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Permissões do proprietário não podem ser alteradas")

    # 5) Concorrência otimista
    if body.expected_version is not None and body.expected_version != target.permissions_version:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Permissões foram alteradas por outra operação; recarregue")

    # 6) Cálculo do diff e anti-escalada de privilégio
    current = set(target.permissions or [])
    requested = {p.value for p in body.permissions}
    added, removed = sorted(requested - current), sorted(current - requested)

    if not set(added + removed) <= effective_permissions(actor):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Você só pode conceder ou revogar permissões que possui")

    if not added and not removed:
        return PermissionUpdateOut(
            user_id=target.id, changed=False, permissions=sorted(current),
            permissions_version=target.permissions_version,
            added=[], removed=[], audit_event_id=None,
        )

    # 7) Alteração + auditoria na mesma transação
    before, after = sorted(current), sorted(requested)
    target.permissions = after
    target.permissions_version += 1
    entry = _append_audit(db, request=request, actor=actor, target=target,
                          before=before, after=after, reason=body.reason)
    db.commit()

    return PermissionUpdateOut(
        user_id=target.id, changed=True, permissions=after,
        permissions_version=target.permissions_version,
        added=added, removed=removed, audit_event_id=entry.event_id,
    )


@router.get("/audit-logs", response_model=AuditPageOut)
def list_audit_logs(
    target_user_id: Optional[uuid.UUID] = None,
    actor_user_id: Optional[uuid.UUID] = None,
    action: Optional[str] = Query(None, max_length=60),
    created_from: Optional[datetime] = None,
    created_to: Optional[datetime] = None,
    cursor: Optional[int] = Query(None, description="seq do último item recebido"),
    limit: int = Query(50, ge=1, le=200),
    actor: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_permission(actor, Permission.AUDIT_READ)

    q = select(AuditLog).where(AuditLog.company_id == actor.company_id)  # isolamento
    if target_user_id:
        q = q.where(AuditLog.target_user_id == target_user_id)
    if actor_user_id:
        q = q.where(AuditLog.actor_user_id == actor_user_id)
    if action:
        q = q.where(AuditLog.action == action)
    if created_from:
        q = q.where(AuditLog.created_at >= created_from)
    if created_to:
        q = q.where(AuditLog.created_at <= created_to)
    if cursor:
        q = q.where(AuditLog.seq < cursor)

    rows = db.execute(q.order_by(AuditLog.seq.desc()).limit(limit + 1)).scalars().all()
    page, has_more = rows[:limit], len(rows) > limit
    return AuditPageOut(
        items=[AuditLogOut.model_validate(r) for r in page],
        next_cursor=page[-1].seq if has_more else None,
    )


@router.get("/audit-logs/verify")
def verify_audit_chain(
    actor: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Recalcula a cadeia de hash do tenant e aponta o primeiro registro adulterado."""
    require_permission(actor, Permission.AUDIT_READ)

    prev: Optional[str] = None
    checked = 0
    stream = db.execute(
        select(AuditLog)
        .where(AuditLog.company_id == actor.company_id)
        .order_by(AuditLog.seq.asc())
        .execution_options(yield_per=500)
    ).scalars()
    for e in stream:
        if e.prev_hash != prev or e.hash != compute_hash(prev, e):
            return {"valid": False, "first_invalid_seq": e.seq, "checked": checked}
        prev, checked = e.hash, checked + 1
    return {"valid": True, "first_invalid_seq": None, "checked": checked}


app = FastAPI(title="SaaS Gestão Empresarial")
app.include_router(router)