from datetime import date
from enum import Enum
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import Decimal, func, select
from sqlalchemy.ext.asyncio import AsyncSession

# --- DTOs (Data Transfer Objects) / Schemas ---

class PeriodEnum(str, Enum):
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUAL = "annual"
    CUSTOM = "custom"

class FinancialReportResponse(BaseModel):
    company_id: int
    period_type: PeriodEnum
    start_date: date
    end_date: date
    total_revenue: float
    total_expenses: float
    net_profit: float
    profit_margin_percentage: float

# --- Dependências simuladas de Contexto e Segurança ---

class CurrentUser(BaseModel):
    id: int
    company_id: int
    role: str

async def get_current_user() -> CurrentUser:
    """
    Simula a extração do usuário autenticado a partir do Token JWT.
    Em produção, valida a assinatura do token e extrai o ID e a Empresa.
    """
    return CurrentUser(id=42, company_id=10, role="admin")

async def get_db_session() -> AsyncSession:
    """Injeta a sessão assíncrona do banco de dados (ex: PostgreSQL)."""
    # Exemplo: yield session
    pass

# --- Rota da API ---

router = APIRouter(prefix="/api/v1/companies", tags=["Financial Reports"])

@router.get(
    "/{company_id}/reports/financial",
    response_model=FinancialReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Gera relatório financeiro consolidado da empresa")
async def get_financial_report(
    company_id: int,
    start_date: date = Query(..., description="Data inicial do período (YYYY-MM-DD)"),
    end_date: date = Query(..., description="Data final do período (YYYY-MM-DD)"),
    period_type: PeriodEnum = Query(PeriodEnum.CUSTOM, description="Tipo de agrupamento visual do período"),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)):
    # 1. Validação Multilocatário (Tenant Isolation)
    if current_user.company_id != company_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado. Você não possui permissão para acessar os dados desta empresa."
        )

    # 2. Validação do Período Solicitação
    if start_date > end_date:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A data inicial não pode ser posterior à data final."
        )

    # 3. Validação do Plano de Assinatura (Feature Flag / Entitlement)
    is_plan_active = await check_company_subscription_and_feature(db, company_id, feature="advanced_reports")
    if not is_plan_active:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="O plano atual da sua assinatura não inclui acesso a relatórios financeiros consolidados."
        )

    # 4. Agregação Consolidada via Banco de Dados
    # Exemplo de consulta otimizada direto na base compartilhada
    query = (
        select(
            func.coalesce(
                func.sum(
                    func.case(
                        (FinancialTransaction.type == 'REVENUE', FinancialTransaction.amount),
                        else_=0
                    )
                ), 0
            ).label("total_revenue"),
            func.coalesce(
                func.sum(
                    func.case(
                        (FinancialTransaction.type == 'EXPENSE', FinancialTransaction.amount),
                        else_=0
                    )
                ), 0
            ).label("total_expenses")
        )
        .where(
            FinancialTransaction.company_id == company_id,  # Garantia adicional de tenant_id
            FinancialTransaction.status == 'COMPLETED',
            FinancialTransaction.transaction_date >= start_date,
            FinancialTransaction.transaction_date <= end_date
        )
    )

    result = await db.execute(query)
    totals = result.one()

    total_revenue = float(totals.total_revenue)
    total_expenses = float(totals.total_expenses)
    net_profit = total_revenue - total_expenses

    profit_margin = 0.0
    if total_revenue > 0:
        profit_margin = round((net_profit / total_revenue) * 100, 2)

    return FinancialReportResponse(
        company_id=company_id,
        period_type=period_type,
        start_date=start_date,
        end_date=end_date,
        total_revenue=total_revenue,
        total_expenses=total_expenses,
        net_profit=net_profit,
        profit_margin_percentage=profit_margin
    )


async def check_company_subscription_and_feature(db: AsyncSession, company_id: int, feature: str) -> bool:
    """
    Verifica se a empresa possui um plano de assinatura ativo e acesso à funcionalidade solicitada.
    """
    # Consulta na tabela Company / Subscription
    return True