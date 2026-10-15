from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import (
    Column, DateTime, ForeignKey, Integer, Numeric, String, Text, select,
)
from sqlalchemy.orm import Session, declarative_base

Base = declarative_base()


# ----------------------------------------------------------------------
# Modelos (simplificados)
# ----------------------------------------------------------------------
class ExpenseStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ExpenseRequest(Base):
    __tablename__ = "expense_requests"

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, nullable=False, index=True)  # tenant
    requester_id = Column(Integer, nullable=False)
    amount = Column(Numeric(14, 2), nullable=False)
    status = Column(String(20), nullable=False, default=ExpenseStatus.PENDING.value)
    approved_by = Column(Integer, nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    approval_comment = Column(Text, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, nullable=False, index=True)
    user_id = Column(Integer, nullable=False)
    action = Column(String(50), nullable=False)
    entity = Column(String(50), nullable=False)
    entity_id = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)


# ----------------------------------------------------------------------
# Contexto de autenticação (resolvido a partir do token validado no servidor).
# `get_db` e `get_current_user` são assumidos como já existentes na aplicação.
# ----------------------------------------------------------------------
class CurrentUser(BaseModel):
    id: int
    company_id: int                       # vem do token/BD, NUNCA do cliente
    permissions: set[str]
    approval_limit: Optional[Decimal] = None  # None = sem limite
    subscription_active: bool


def get_db() -> Session: ...                      # fornecido pela aplicação
def get_current_user() -> CurrentUser: ...        # fornecido pela aplicação


# ----------------------------------------------------------------------
# Schemas
# ----------------------------------------------------------------------
class ApprovalIn(BaseModel):
    comment: Optional[str] = Field(default=None, max_length=1000)


class ApprovalOut(BaseModel):
    id: int
    status: ExpenseStatus
    approved_by: int
    approved_at: datetime
    message: str


# ----------------------------------------------------------------------
# Rota
# ----------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/expense-requests", tags=["expense-requests"])


@router.post(
    "/{request_id}/approve",
    response_model=ApprovalOut,
    status_code=status.HTTP_200_OK,
)
def approve_expense_request(
    request_id: int,
    payload: ApprovalIn,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ApprovalOut:
    # 1) Assinatura ativa da empresa
    if not user.subscription_active:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED,
                            "Assinatura da empresa inativa.")

    # 2) Autorização: o usuário precisa ter permissão de aprovar despesas
    if "expenses:approve" not in user.permissions:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Sem permissão para aprovar despesas.")

    try:
        # 3) Busca ESCOPADA PELO TENANT + lock de linha (evita aprovação concorrente).
        #    Se o ID existir em outra empresa, o resultado é idêntico a "não existe",
        #    o que impede enumeração de recursos entre locatários (IDOR).
        expense = db.execute(
            select(ExpenseRequest)
            .where(
                ExpenseRequest.id == request_id,
                ExpenseRequest.company_id == user.company_id,
            )
            .with_for_update()
        ).scalar_one_or_none()

        if expense is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                "Solicitação não encontrada.")

        # 4) Segregação de funções: ninguém aprova a própria despesa
        if expense.requester_id == user.id:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "Não é permitido aprovar a própria solicitação.")

        # 5) Alçada de aprovação
        if user.approval_limit is not None and expense.amount > user.approval_limit:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "Valor acima da sua alçada de aprovação.")

        # 6) Transição de estado válida (somente PENDING -> APPROVED)
        if expense.status != ExpenseStatus.PENDING.value:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Solicitação não pode ser aprovada no estado {expense.status}.",
            )

        # 7) Atualização do estado + trilha de auditoria na MESMA transação
        now = datetime.now(timezone.utc)
        expense.status = ExpenseStatus.APPROVED.value
        expense.approved_by = user.id
        expense.approved_at = now
        expense.approval_comment = payload.comment

        db.add(AuditLog(
            company_id=user.company_id,
            user_id=user.id,
            action="EXPENSE_APPROVED",
            entity="expense_request",
            entity_id=expense.id,
            created_at=now,
        ))

        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            "Erro ao processar a aprovação.")

    return ApprovalOut(
        id=expense.id,
        status=ExpenseStatus.APPROVED,
        approved_by=user.id,
        approved_at=now,
        message="Solicitação de despesa aprovada com sucesso.",
    )