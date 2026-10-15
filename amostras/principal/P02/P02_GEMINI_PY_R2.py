from datetime import date
from enum import Enum
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Decimal, Exception as SQLAlchemyError, func, select
from sqlalchemy.ext.asyncio import AsyncSession

# ==============================================================================
# ENUMS E ESQUEMAS (Pydantic v2)
# ==============================================================================

class SubscriptionStatus(str, Enum):
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    TRIAL = "trial"

class ConsolidatedFinancialReport(BaseModel):
    company_id: int
    period_start: date
    period_end: date
    total_revenues: Decimal = Field(..., description="Total de receitas no período")
    total_expenses: Decimal = Field(..., description="Total de despesas no período")
    net_profit: Decimal = Field(..., description="Lucro líquido (Receitas - Despesas)")
    total_transactions: int = Field(..., description="Quantidade total de transações processadas")

    model_config = ConfigDict(from_attributes=True)

# ==============================================================================
# MOCK DE DEPENDÊNCIAS DE INFRAESTRUTURA E AUTENTICAÇÃO
# ==============================================================================

class UserContext:
    def __init__(self, user_id: int, company_id: int, is_admin: bool = False):
        self.user_id = user_id
        self.company_id = company_id
        self.is_admin = is_admin

async def get_current_user() -> UserContext:
    """
    Injeta o contexto do usuário autenticado a partir do Token JWT.
    Substitua pela sua lógica real de segurança.
    """
    return UserContext(user_id=42, company_id=101)

async def get_db_session():
    """Provedor da sessão assíncrona do banco de dados (SQLAlchemy)."""
    # Exemplo mockado do gerador de sessão
    yield None

# ==============================================================================
# ROTA DA API
# ==============================================================================

router = APIRouter(prefix="/api/v1/companies", tags=["Financial Reports"])

@router.get(
    "/{company_id}/reports/financial",
    response_model=ConsolidatedFinancialReport,
    status_code=status.HTTP_200_OK,
    summary="Gera relatório financeiro consolidado",
    description="Retorna o resumo consolidado de receitas, despesas e lucro líquido de uma empresa em um período especifico.")
async def get_consolidated_financial_report(
    company_id: int,
    start_date: Annotated[date, Query(description="Data inicial (AAAA-MM-DD)")],
    end_date: Annotated[date, Query(description="Data final (AAAA-MM-DD)")],
    current_user: Annotated[UserContext, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)]):
    # 1. Validação do Período Solicidato
    if start_date > end_date:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A data inicial não pode ser posterior à data final."
        )

    # 2. Isolamento Multi-tenant (Segurança e Autorização)
    # Impede que usuários de uma empresa acessem dados de outra empresa
    if current_user.company_id != company_id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: você não possui permissão para visualizar relatórios desta empresa."
        )

    try:
        # 3. Verificação de existência da empresa e status da assinatura
        # Supondo a existência dos modelos SQLAlchemy 'Company' e 'Transaction'
        from models import Company, Transaction, TransactionType

        company_query = select(Company.subscription_status).where(Company.id == company_id)
        result = await db.execute(company_query)
        company_status = result.scalar_one_or_none()

        if company_status is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Empresa cliente não encontrada."
            )

        if company_status not in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL]:
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail="Assinatura inativa ou pendente de pagamento. Atualize o plano para acessar relatórios."
            )

        # 4. Agregação Direta no Banco de Dados (Consulta Performática)
        stmt = (
            select(
                func.coalesce(
                    func.sum(Transaction.amount).filter(Transaction.type == TransactionType.REVENUE),
                    0
                ).label("total_revenues"),
                func.coalesce(
                    func.sum(Transaction.amount).filter(Transaction.type == TransactionType.EXPENSE),
                    0
                ).label("total_expenses"),
                func.count(Transaction.id).label("total_transactions")
            )
            .where(
                Transaction.company_id == company_id,
                Transaction.date >= start_date,
                Transaction.date <= end_date
            )
        )

        report_data = (await db.execute(stmt)).one()

        total_revenues = Decimal(str(report_data.total_revenues))
        total_expenses = Decimal(str(report_data.total_expenses))
        net_profit = total_revenues - total_expenses

        # 5. Retorno dos dados formatados via Pydantic
        return ConsolidatedFinancialReport(
            company_id=company_id,
            period_start=start_date,
            period_end=end_date,
            total_revenues=total_revenues,
            total_expenses=total_expenses,
            net_profit=net_profit,
            total_transactions=report_data.total_transactions
        )

    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        # Logar erro internamente
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao processar a consulta do relatório financeiro."
        )