from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, Enum, ForeignKey, Numeric, String, select
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# ---------------------------------------------------------------------------
# Modelos (simplificados)
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class ExpenseStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class ExpenseRequest(Base):
    __tablename__ = "expense_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    company_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("companies.id"), index=True
    )
    requester_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    amount: Mapped[Decimal] = mapped_column(Numeric(14, 2))
    currency: Mapped[str] = mapped_column(String(3))
    status: Mapped[ExpenseStatus] = mapped_column(
        Enum(ExpenseStatus), default=ExpenseStatus.PENDING
    )
    approved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    approval_comment: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    company_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    actor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    action: Mapped[str] = mapped_column(String(64))
    resource_type: Mapped[str] = mapped_column(String(64))
    resource_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# ---------------------------------------------------------------------------
# Contexto de autenticação
# ---------------------------------------------------------------------------


class AuthContext(BaseModel):
    """Identidade extraída do token JWT JÁ VALIDADO (assinatura, expiração).

    company_id vem do token/sessão, NUNCA do corpo ou da URL da requisição.
    """

    user_id: uuid.UUID
    company_id: uuid.UUID
    permissions: frozenset[str]
    approval_limit: Optional[Decimal] = None  # None = sem limite
    subscription_active: bool


def get_db() -> Session:  # injeção da sessão do banco (implementação do projeto)
    raise NotImplementedError


def get_auth_context() -> AuthContext:  # valida o token (implementação do projeto)
    raise NotImplementedError


def require_active_subscription(
    ctx: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    if not ctx.subscription_active:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Assinatura da empresa inativa.",
        )
    return ctx


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ApprovalIn(BaseModel):
    comment: Optional[str] = Field(default=None, max_length=500)


class ApprovalOut(BaseModel):
    id: uuid.UUID
    status: ExpenseStatus
    approved_by: uuid.UUID
    approved_at: datetime
    message: str


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/expense-requests", tags=["expense-requests"])


@router.post(
    "/{request_id}/approve",
    response_model=ApprovalOut,
    status_code=status.HTTP_200_OK,
)
def approve_expense_request(
    request_id: uuid.UUID,
    payload: ApprovalIn,
    ctx: AuthContext = Depends(require_active_subscription),
    db: Session = Depends(get_db),
) -> ApprovalOut:
    # 1) Autorização por permissão (RBAC)
    if "expenses:approve" not in ctx.permissions:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para aprovar despesas.")

    # 2) Busca com isolamento de tenant + lock de linha (evita dupla aprovação concorrente).
    #    Se o registro pertence a outra empresa, retorna 404 (não vaza existência).
    stmt = (
        select(ExpenseRequest)
        .where(
            ExpenseRequest.id == request_id,
            ExpenseRequest.company_id == ctx.company_id,
        )
        .with_for_update()
    )
    expense = db.execute(stmt).scalar_one_or_none()
    if expense is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Solicitação não encontrada.")

    # 3) Regras de negócio
    if expense.requester_id == ctx.user_id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Não é permitido aprovar a própria solicitação."
        )

    if ctx.approval_limit is not None and expense.amount > ctx.approval_limit:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Valor acima da sua alçada de aprovação."
        )

    if expense.status != ExpenseStatus.PENDING:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Solicitação não está pendente (estado atual: {expense.status.value}).",
        )

    # 4) Transição de estado + trilha de auditoria na MESMA transação
    now = datetime.now(timezone.utc)
    expense.status = ExpenseStatus.APPROVED
    expense.approved_by = ctx.user_id
    expense.approved_at = now
    expense.approval_comment = payload.comment

    db.add(
        AuditLog(
            id=uuid.uuid4(),
            company_id=ctx.company_id,
            actor_id=ctx.user_id,
            action="expense_request.approved",
            resource_type="expense_request",
            resource_id=expense.id,
            details={"amount": str(expense.amount), "currency": expense.currency},
            created_at=now,
        )
    )

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "Falha ao registrar a aprovação."
        )

    return ApprovalOut(
        id=expense.id,
        status=expense.status,
        approved_by=ctx.user_id,
        approved_at=now,
        message="Solicitação de despesa aprovada com sucesso.",
    )