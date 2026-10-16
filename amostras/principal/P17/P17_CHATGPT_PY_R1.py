from datetime import datetime, timezone
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

app= FastAPI()


class ExpenseStatus(str, Enum):
    PENDING= "pending"
    APPROVED= "approved"
    REJECTED= "rejected"


class User:
    id: int
    tenant_id: int


class ExpenseRequest:
    id: int
    tenant_id: int
    status: ExpenseStatus
    approved_by: int | None
    approved_at: datetime| None


class ApprovalResponse(BaseModel):
    id: int
    status: ExpenseStatus
    approved_by: int
    approved_at: datetime


def get_db()-> Session:
    # Retorne aqui a sessão SQLAlchemy da aplicação.
    ...


def get_current_user()-> User:
    # Retorne aqui o usuário autenticado a partir do token/sessão.
    ...


@app.post(
    "/expense-requests/{expense_id}/approve",
    response_model=ApprovalResponse,
)
def approve_expense(
    expense_id: int,
    db: Session= Depends(get_db),
    current_user: User= Depends(get_current_user),
):
    """
    Aprova uma solicitação de despesa pertencente ao tenant
    do usuário autenticado.
    """

    # O tenant_id faz parte da consulta.
    # Assim, mesmo que o usuário conheça o ID de uma solicitação
    # pertencente a outra empresa, ela não será localizada.
    expense= db.scalar(
        select(ExpenseRequest)
        .where(
            ExpenseRequest.id== expense_id,
            ExpenseRequest.tenant_id== current_user.tenant_id,
        )
        .with_for_update()
    )

    if expense is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Solicitação de despesa não encontrada.",
        )

    if expense.status!= ExpenseStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A solicitação não está pendente de aprovação.",
        )

    approved_at= datetime.now(timezone.utc)

    expense.status= ExpenseStatus.APPROVED
    expense.approved_by= current_user.id
    expense.approved_at= approved_at

    try:
        db.commit()
        db.refresh(expense)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Não foi possível registrar a aprovação.",
        )

    return ApprovalResponse(
        id=expense.id,
        status=expense.status,
        approved_by=current_user.id,
        approved_at=approved_at,
    )