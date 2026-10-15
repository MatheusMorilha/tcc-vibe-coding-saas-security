from datetime import date
from decimal import Decimal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from database import get_db
from models import Company, FinancialTransaction


app = FastAPI()


class FinancialReport(BaseModel):
    company_id: int
    start_date: date
    end_date: date
    total_income: Decimal
    total_expenses: Decimal
    balance: Decimal


@app.get(
    "/companies/{company_id}/financial-report",
    response_model=FinancialReport,
)
def get_financial_report(
    company_id: int,
    start_date: date = Query(...),
    end_date: date = Query(...),
    db: Session = next(get_db()),
):
    # Validação do período
    if start_date > end_date:
        raise HTTPException(
            status_code=400,
            detail="start_date deve ser menor ou igual a end_date.",
        )

    # Garante que a empresa existe.
    company = db.scalar(
        select(Company).where(Company.id == company_id)
    )

    if company is None:
        raise HTTPException(
            status_code=404,
            detail="Empresa não encontrada.",
        )

    # Todas as consultas financeiras são obrigatoriamente
    # filtradas pelo company_id para impedir vazamento entre tenants.
    income = db.scalar(
        select(func.coalesce(func.sum(FinancialTransaction.amount), 0))
        .where(
            FinancialTransaction.company_id == company_id,
            FinancialTransaction.transaction_type == "income",
            FinancialTransaction.transaction_date >= start_date,
            FinancialTransaction.transaction_date <= end_date,
        )
    )

    expenses = db.scalar(
        select(func.coalesce(func.sum(FinancialTransaction.amount), 0))
        .where(
            FinancialTransaction.company_id == company_id,
            FinancialTransaction.transaction_type == "expense",
            FinancialTransaction.transaction_date >= start_date,
            FinancialTransaction.transaction_date <= end_date,
        )
    )

    income = Decimal(income)
    expenses = Decimal(expenses)
    balance = income - expenses

    return FinancialReport(
        company_id=company_id,
        start_date=start_date,
        end_date=end_date,
        total_income=income,
        total_expenses=expenses,
        balance=balance,
    )
