from datetime import datetime, timezone
from enum import Enum
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ExpenseRequest, User


router= APIRouter(prefix="/expense-requests", tags=["Expense Requests"])


class ExpenseStatus(str, Enum):
    PENDING= "pending"
    APPROVED= "approved"
    REJECTED= "rejected"


class CurrentUser(BaseModel):
    id: UUID
    tenant_id: UUID


def get_current_user()-> CurrentUser:
    """
    Em produção, este contexto deve ser construído a partir
    do token/sessão autenticado.
    """
    raise NotImplementedError


@router.post(
    "/{expense_request_id}/approve",
    status_code=status.HTTP_200_OK,
)
def approve_expense_request(
    expense_request_id: UUID,
    db: Session= Depends(get_db),
    current_user: CurrentUser= Depends(get_current_user),
):
    # O tenant_id é obtido da identidade autenticada.
    # Não deve ser aceito como parâmetro da requisição.
    stmt= (
        select(ExpenseRequest)
        .where(
            ExpenseRequest.id== expense_request_id,
            ExpenseRequest.tenant_id== current_user.tenant_id,
        )
        .with_for_update()
    )

    expense= db.execute(stmt).scalar_one_or_none()

    if expenseis None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Solicitação de despesa não encontrada.",
        )

    # Evita que uma solicitação já encerrada seja aprovada novamente.
    if expense.status!= ExpenseStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A solicitação já está no estado '{expense.status}'.",
        )

    # Opcionalmente, valide aqui permissões específicas do usuário.
    # Ex.: somente usuários com papel "manager" podem aprovar.
    user_stmt= select(User).where(
        User.id== current_user.id,
        User.tenant_id== current_user.tenant_id,
    )

    user= db.execute(user_stmt).scalar_one_or_none()

    if useris None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuário não pertence à empresa.",
        )

    if not user.can_approve_expenses:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuário não possui permissão para aprovar despesas.",
        )

    now= datetime.now(timezone.utc)

    expense.status= ExpenseStatus.APPROVED
    expense.approved_by= current_user.id
    expense.approved_at= now

    db.commit()
    db.refresh(expense)

    return {
        "success": True,
        "message": "Solicitação de despesa aprovada com sucesso.",
        "data": {
            "id": str(expense.id),
            "status": expense.status,
            "approved_by": str(expense.approved_by),
            "approved_at": expense.approved_at.isoformat(),
        },
    }