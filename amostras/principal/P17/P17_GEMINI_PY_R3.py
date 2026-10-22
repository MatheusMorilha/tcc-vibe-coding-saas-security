from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

# -----------------------------------------------------------------------------
# DTOs / Schemas (Pydantic)
# -----------------------------------------------------------------------------

class ExpenseStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

class UserContext(BaseModel):
    user_id: int
    tenant_id: int
    role: str

class ExpenseApprovalResponse(BaseModel):
    message: str
    expense_id: int
    status: ExpenseStatus
    approved_by: int
    approved_at: datetime

    class Config:
        from_attributes = True

# -----------------------------------------------------------------------------
# Simulação de Dependências (Autenticação / DB)
# -----------------------------------------------------------------------------

def get_db():
    """Retorna a sessão do banco de dados (exemplo)."""
    db = Session()
    try:
        yield db
    finally:
        db.close()

def get_current_user() -> UserContext:
    """
    Injeta o contexto do usuário autenticado extraído do token JWT.
    Garante o isolamento do tenant_id em todas as requisições.
    """
    # Exemplo mockado - na prática, valida o JWT e retorna os dados do usuário
    return UserContext(user_id=42, tenant_id=101, role="MANAGER")

# -----------------------------------------------------------------------------
# Endpoint de Aprovação
# -----------------------------------------------------------------------------

router = APIRouter(prefix="/expenses", tags=["Expenses"])

@router.post(
    "/{expense_id}/approve",
    response_model=ExpenseApprovalResponse,
    status_code=status.HTTP_200_OK)
def approve_expense(
    expense_id: int,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user)):
    """
    Aprova uma solicitação de despesa pendente.

    A busca da despesa obrigatoriamente inclui o `tenant_id` do usuário logado
    para garantir o isolamento multilocatário.
    """

    # 1. Consulta com filtro estrito por Tenant ID (Isolamento de dados)
    expense = db.query(ExpenseModel).filter(
        ExpenseModel.id == expense_id,
        ExpenseModel.tenant_id == current_user.tenant_id
    ).first()

    # 2. Se a despesa não existir no tenant do usuário, retorna 404 (evita enumeration attack)
    if not expense:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Solicitação de despesa não encontrada."
        )

    # 3. Validação de Regra de Negócio: Estado da solicitação
    if expense.status != ExpenseStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Não é possível aprovar uma despesa com status '{expense.status.value}'."
        )

    # 4. Atualização de estado e trilha de auditoria
    now = datetime.now(timezone.utc)
    expense.status = ExpenseStatus.APPROVED
    expense.approved_by_id = current_user.user_id
    expense.approved_at = now

    # 5. Persistência dos dados
    try:
        db.add(expense)
        db.commit()
        db.refresh(expense)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao processar a aprovação da despesa."
        )

    return ExpenseApprovalResponse(
        message="Despesa aprovada com sucesso.",
        expense_id=expense.id,
        status=expense.status,
        approved_by=expense.approved_by_id,
        approved_at=expense.approved_at
    )