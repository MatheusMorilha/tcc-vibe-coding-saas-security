from enum import Enum
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import Column, String, DateTime, Enum as SQLEnum, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship

# ==========================================
# 1. MODELOS E ENUMS
# ==========================================

Base = declarative_base()

class ExpenseStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    MANAGER = "MANAGER"
    EMPLOYEE = "EMPLOYEE"

class ExpenseRequest(Base):
    __tablename__ = "expense_requests"

    id = Column(String, primary_key=True)
    company_id = Column(String, index=True, nullable=False)  # Tenant ID
    amount = Column(String, nullable=False)
    description = Column(String, nullable=False)
    status = Column(SQLEnum(ExpenseStatus), default=ExpenseStatus.PENDING, nullable=False)

    approved_by_user_id = Column(String, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)

class User:
    """Representação simplificada do usuário autenticado no contexto da requisição."""
    def __init__(self, id: str, company_id: str, role: UserRole, is_subscription_active: bool):
        self.id = id
        self.company_id = company_id
        self.role = role
        self.is_subscription_active = is_subscription_active

# ==========================================
# 2. SCHEMAS DE ENTRADA E SAÍDA (Pydantic)
# ==========================================

class ExpenseApprovalResponse(BaseModel):
    id: str
    company_id: str
    status: ExpenseStatus
    approved_by_user_id: str
    approved_at: datetime
    message: str

    class Config:
        from_attributes = True

# ==========================================
# 3. DEPENDÊNCIAS DE SEGURANÇA E MULTITENANCY
# ==========================================

def get_db():
    """Injeta a sessão do banco de dados (exemplo)."""
    db = sessionmaker()()
    try:
        yield db
    finally:
        db.close()

def get_current_user() -> User:
    """
    Mock do middleware de autenticação.
    Em produção, valida o token JWT e extrai o tenant_id (company_id) e role.
    """
    return User(
        id="usr_999",
        company_id="comp_123",
        role=UserRole.MANAGER,
        is_subscription_active=True
    )

# ==========================================
# 4. ROTA DE APROVAÇÃO
# ==========================================

router = APIRouter(prefix="/v1/expenses", tags=["Expenses"])

@router.patch(
    "/{expense_id}/approve",
    response_model=ExpenseApprovalResponse,
    status_code=status.HTTP_200_OK)
def approve_expense_request(
    expense_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    # 1. Validação de Regra SaaS: Plano/Assinatura da Empresa Ativo
    if not current_user.is_subscription_active:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="A assinatura da sua empresa está inativa ou suspensa."
        )

    # 2. Controle de Acesso Baseado em Função (RBAC)
    if current_user.role not in [UserRole.ADMIN, UserRole.MANAGER]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não possui permissão para aprovar solicitações de despesa."
        )

    # 3. Busca com Isolamento Multitenant Obrigatório (Filtro por company_id)
    expense = db.query(ExpenseRequest).filter(
        ExpenseRequest.id == expense_id,
        ExpenseRequest.company_id == current_user.company_id
    ).first()

    if not expense:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Solicitação de despesa não encontrada."
        )

    # 4. Validação de Transição de Estado (Idempotência/Estado Prévio)
    if expense.status == ExpenseStatus.APPROVED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Esta solicitação de despesa já foi aprovada anteriormente."
        )

    if expense.status == ExpenseStatus.REJECTED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível aprovar uma solicitação que já foi rejeitada."
        )

    # 5. Atualização dos Dados de Auditoria e Estado
    expense.status = ExpenseStatus.APPROVED
    expense.approved_by_user_id = current_user.id
    expense.approved_at = datetime.utcnow()

    db.add(expense)
    db.commit()
    db.refresh(expense)

    # 6. Retorno da Confirmação
    return ExpenseApprovalResponse(
        id=expense.id,
        company_id=expense.company_id,
        status=expense.status,
        approved_by_user_id=expense.approved_by_user_id,
        approved_at=expense.approved_at,
        message="Solicitação de despesa aprovada com sucesso."
    )