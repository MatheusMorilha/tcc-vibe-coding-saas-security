"""
financial_report.py

Rota de API para geração de relatório financeiro consolidado
de uma empresa cliente (tenant) em uma plataforma SaaS multilocatária.

Stack: FastAPI + SQLAlchemy (assíncrono)

Pontos de atenção implementados:
- Isolamento estrito de tenant (nenhuma query financeira roda sem
  filtrar explicitamente por company_id).
- Validação de que o usuário autenticado pertence (ou tem permissão
  explícita de acesso) à empresa solicitada.
- Validação de período (datas, intervalo máximo, empresa ativa).
- Consulta agregada no banco (evita trazer todas as transações para
  a aplicação e somar em memória).
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.auth.dependencies import get_current_user, CurrentUser
from app.models.company import Company
from app.models.transaction import Transaction, TransactionType

router = APIRouter(prefix="/companies", tags=["financial-reports"])

MAX_PERIOD_DAYS = 366  # limite defensivo para evitar consultas muito pesadas


# ---------------------------------------------------------------------------
# Schemas de entrada/saída
# ---------------------------------------------------------------------------

class FinancialReportQuery(BaseModel):
    start_date: date = Field(..., description="Início do período (inclusive)")
    end_date: date = Field(..., description="Fim do período (inclusive)")

    @model_validator(mode="after")
    def validate_period(self) -> "FinancialReportQuery":
        if self.end_date < self.start_date:
            raise ValueError("end_date não pode ser anterior a start_date")
        if (self.end_date - self.start_date).days > MAX_PERIOD_DAYS:
            raise ValueError(
                f"Período máximo permitido é de {MAX_PERIOD_DAYS} dias"
            )
        return self


class FinancialReportResponse(BaseModel):
    company_id: UUID
    company_name: str
    period_start: date
    period_end: date
    total_revenue: float
    total_expenses: float
    net_result: float
    transaction_count: int
    generated_at: datetime


# ---------------------------------------------------------------------------
# Autorização: garante que o usuário só acesse dados da(s) empresa(s)
# às quais pertence, salvo perfil com permissão explícita de auditoria.
# ---------------------------------------------------------------------------

def _ensure_tenant_access(current_user: CurrentUser, company_id: UUID) -> None:
    is_same_tenant = current_user.company_id == company_id
    has_cross_tenant_permission = "reports:read:any_company" in current_user.permissions

    if not (is_same_tenant or has_cross_tenant_permission):
        # 404 em vez de 403 evita confirmar a existência do company_id
        # para quem não tem relação nenhuma com aquele tenant.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Empresa não encontrada.",
        )


# ---------------------------------------------------------------------------
# Rota
# ---------------------------------------------------------------------------

@router.get(
    "/{company_id}/reports/financial-summary",
    response_model=FinancialReportResponse,
    summary="Relatório financeiro consolidado de uma empresa no período informado",
)
async def get_financial_report(
    company_id: UUID,
    start_date: date = Query(..., description="Data inicial (YYYY-MM-DD)"),
    end_date: date = Query(..., description="Data final (YYYY-MM-DD)"),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> FinancialReportResponse:
    # 1. Autorização de tenant (antes de qualquer consulta a dados financeiros)
    _ensure_tenant_access(current_user, company_id)

    # 2. Validação do período (datas coerentes, intervalo dentro do limite)
    try:
        period = FinancialReportQuery(start_date=start_date, end_date=end_date)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    # 3. Confirma que a empresa existe e está com assinatura ativa
    company_stmt = select(Company).where(Company.id == company_id)
    company = (await db.execute(company_stmt)).scalar_one_or_none()

    if company is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Empresa não encontrada.",
        )

    if not company.subscription_active:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="A assinatura desta empresa não está ativa.",
        )

    # 4. Consulta agregada, sempre filtrada por company_id (isolamento de tenant)
    revenue_stmt = select(func.coalesce(func.sum(Transaction.amount), 0)).where(
        Transaction.company_id == company_id,
        Transaction.type == TransactionType.REVENUE,
        Transaction.occurred_at >= period.start_date,
        Transaction.occurred_at <= period.end_date,
    )
    expenses_stmt = select(func.coalesce(func.sum(Transaction.amount), 0)).where(
        Transaction.company_id == company_id,
        Transaction.type == TransactionType.EXPENSE,
        Transaction.occurred_at >= period.start_date,
        Transaction.occurred_at <= period.end_date,
    )
    count_stmt = select(func.count(Transaction.id)).where(
        Transaction.company_id == company_id,
        Transaction.occurred_at >= period.start_date,
        Transaction.occurred_at <= period.end_date,
    )

    total_revenue = (await db.execute(revenue_stmt)).scalar_one()
    total_expenses = (await db.execute(expenses_stmt)).scalar_one()
    transaction_count = (await db.execute(count_stmt)).scalar_one()

    return FinancialReportResponse(
        company_id=company.id,
        company_name=company.name,
        period_start=period.start_date,
        period_end=period.end_date,
        total_revenue=float(total_revenue),
        total_expenses=float(total_expenses),
        net_result=float(total_revenue) - float(total_expenses),
        transaction_count=transaction_count,
        generated_at=datetime.utcnow(),
    )