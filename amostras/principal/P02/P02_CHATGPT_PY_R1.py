from datetime import date, datetime, time
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import (
    DateTime,
    ForeignKey,
    Numeric,
    String,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# ---------------------------------------------------------------------------
# Banco / modelos
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class Company(Base):
    __tablename__ = "companies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))


class UserCompany(Base):
    __tablename__ = "user_companies"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        primary_key=True,
    )
    company_id: Mapped[int] = mapped_column(
        ForeignKey("companies.id"),
        primary_key=True,
    )


class FinancialTransaction(Base):
    __tablename__ = "financial_transactions"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Tenant ao qual o lançamento pertence.
    company_id: Mapped[int] = mapped_column(
        ForeignKey("companies.id"),
        index=True,
    )

    transaction_date: Mapped[datetime] = mapped_column(
        DateTime,
        index=True,
    )

    # "revenue" ou "expense"
    transaction_type: Mapped[str] = mapped_column(String(20))

    amount: Mapped[Decimal] = mapped_column(
        Numeric(15, 2),
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class FinancialReport(BaseModel):
    company_id: int
    start_date: date
    end_date: date
    revenue: Decimal
    expenses: Decimal
    profit: Decimal


# ---------------------------------------------------------------------------
# Dependências
# ---------------------------------------------------------------------------

def get_db() -> Session:
    """
    Substitua pela implementação real de criação da sessão SQLAlchemy.
    """
    raise NotImplementedError


class AuthenticatedUser(BaseModel):
    id: int


def get_current_user() -> AuthenticatedUser:
    """
    Substitua pela validação real do JWT/session.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api",
    tags=["financial"],
)


@router.get(
    "/companies/{company_id}/financial-report",
    response_model=FinancialReport,
)
def get_financial_report(
    company_id: int,
    start_date: date = Query(
        ...,
        description="Data inicial do relatório.",
    ),
    end_date: date = Query(
        ...,
        description="Data final do relatório.",
    ),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FinancialReport:
    """
    Retorna o relatório financeiro consolidado de uma empresa.

    Exemplo:

    GET /api/companies/42/financial-report
        ?start_date=2026-01-01
        &end_date=2026-01-31
    """

    # ---------------------------------------------------------------
    # 1. Validação do período
    # ---------------------------------------------------------------

    if start_date > end_date:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_date deve ser menor ou igual a end_date.",
        )

    # ---------------------------------------------------------------
    # 2. Verificação de acesso ao tenant
    #
    # IMPORTANTE:
    # Não devemos simplesmente consultar:
    #
    #     FinancialTransaction.company_id == company_id
    #
    # sem antes garantir que o usuário possui acesso à empresa.
    # ---------------------------------------------------------------

    membership_query = select(UserCompany).where(
        UserCompany.user_id == current_user.id,
        UserCompany.company_id == company_id,
    )

    membership = db.scalar(membership_query)

    if membership is None:
        # Retornamos 404 para não revelar a existência de uma empresa
        # à qual o usuário não possui acesso.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Empresa não encontrada.",
        )

    # ---------------------------------------------------------------
    # 3. Verificação da empresa
    # ---------------------------------------------------------------

    company_query = select(Company).where(
        Company.id == company_id,
    )

    company = db.scalar(company_query)

    if company is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Empresa não encontrada.",
        )

    # ---------------------------------------------------------------
    # 4. Definição do intervalo de datas
    #
    # Usamos intervalo semiaberto:
    #
    #     >= início
    #     < dia seguinte ao fim
    #
    # Assim registros do último dia não são perdidos por causa
    # do componente de horário.
    # ---------------------------------------------------------------

    start_datetime = datetime.combine(
        start_date,
        time.min,
    )

    end_datetime_exclusive = datetime.combine(
        end_date,
        time.max,
    )

    # ---------------------------------------------------------------
    # 5. Agregação diretamente no banco
    #
    # Não carregamos todas as transações para a aplicação.
    # O banco calcula os totais.
    # ---------------------------------------------------------------

    revenue_expression = func.coalesce(
        func.sum(
            FinancialTransaction.amount
        ).filter(
            FinancialTransaction.transaction_type == "revenue"
        ),
        0,
    )

    expense_expression = func.coalesce(
        func.sum(
            FinancialTransaction.amount
        ).filter(
            FinancialTransaction.transaction_type == "expense"
        ),
        0,
    )

    report_query = select(
        revenue_expression.label("revenue"),
        expense_expression.label("expenses"),
    ).where(
        # -----------------------------------------------------------
        # REGRA FUNDAMENTAL DE MULTITENANCY:
        #
        # Toda consulta financeira deve filtrar explicitamente
        # pelo tenant.
        # -----------------------------------------------------------
        FinancialTransaction.company_id == company_id,

        FinancialTransaction.transaction_date >= start_datetime,
        FinancialTransaction.transaction_date <= end_datetime_exclusive,
    )

    result = db.execute(report_query).one()

    revenue = Decimal(result.revenue or 0)
    expenses = Decimal(result.expenses or 0)
    profit = revenue - expenses

    # ---------------------------------------------------------------
    # 6. Resposta consolidada
    # ---------------------------------------------------------------

    return FinancialReport(
        company_id=company.id,
        start_date=start_date,
        end_date=end_date,
        revenue=revenue,
        expenses=expenses,
        profit=profit,
    )
