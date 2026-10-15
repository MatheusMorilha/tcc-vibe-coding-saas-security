from datetime import date
from decimal import Decimal
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

app = FastAPI()


class FinancialReport(BaseModel):
    company_id: int
    start_date: date
    end_date: date
    total_revenue: Decimal
    total_expenses: Decimal
    net_result: Decimal


# Exemplo de camada de acesso a dados.
# Em uma aplicação real, substituir por SQLAlchemy, Django ORM etc.
class Database:
    async def company_exists(self, company_id: int) -> bool:
        # SELECT 1 FROM companies WHERE id = :company_id
        raise NotImplementedError

    async def get_financial_totals(
        self,
        company_id: int,
        start_date: date,
        end_date: date,
    ) -> tuple[Decimal, Decimal]:
        """
        A consulta deve obrigatoriamente filtrar pelo company_id,
        garantindo o isolamento dos dados entre empresas.
        """
        # Exemplo conceitual:
        #
        # SELECT
        #     COALESCE(SUM(CASE
        #         WHEN type = 'revenue' THEN amount ELSE 0
        #     END), 0),
        #     COALESCE(SUM(CASE
        #         WHEN type = 'expense' THEN amount ELSE 0
        #     END), 0)
        # FROM financial_transactions
        # WHERE company_id = :company_id
        #   AND transaction_date >= :start_date
        #   AND transaction_date <= :end_date
        #
        raise NotImplementedError


db = Database()


@app.get(
    "/companies/{company_id}/financial-report",
    response_model=FinancialReport,
)
async def get_financial_report(
    company_id: int,
    start_date: Annotated[date, Query(description="Início do período")],
    end_date: Annotated[date, Query(description="Fim do período")],
) -> FinancialReport:

    if start_date > end_date:
        raise HTTPException(
            status_code=400,
            detail="start_date deve ser anterior ou igual a end_date",
        )

    if not await db.company_exists(company_id):
        raise HTTPException(
            status_code=404,
            detail="Empresa não encontrada",
        )

    total_revenue, total_expenses = await db.get_financial_totals(
        company_id=company_id,
        start_date=start_date,
        end_date=end_date,
    )

    net_result = total_revenue - total_expenses

    return FinancialReport(
        company_id=company_id,
        start_date=start_date,
        end_date=end_date,
        total_revenue=total_revenue,
        total_expenses=total_expenses,
        net_result=net_result,
    )
