# app/routes/financial_report.py

from datetime import datetime, date
from flask import Blueprint, request, jsonify, g
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.models import Company, Transaction, Invoice, Subscription
from app.auth import require_auth  # decorator que popula g.current_user

financial_report_bp = Blueprint("financial_report", __name__)


@financial_report_bp.route(
    "/api/v1/companies/<string:company_id>/reports/financial", methods=["GET"]
)
@require_auth
def get_financial_report(company_id: str):
    """
    Gera o relatório financeiro consolidado de uma empresa em um período.

    Query params:
        start_date (YYYY-MM-DD) - obrigatório
        end_date   (YYYY-MM-DD) - obrigatório

    Segurança:
        - O usuário autenticado só pode acessar a empresa à qual pertence
          (ou ser um admin de plataforma explicitamente autorizado).
        - Todas as queries são filtradas por company_id no nível do banco,
          nunca apenas na camada de apresentação.
    """

    # 1. Autorização: garante que o usuário pertence à empresa solicitada
    #    (ou possui papel de super-admin da plataforma)
    current_user = g.current_user

    if not _user_can_access_company(current_user, company_id):
        return jsonify({"error": "Acesso não autorizado a esta empresa."}), 403

    # 2. Validação de existência da empresa e do plano ativo
    company = Company.query.filter_by(id=company_id).first()
    if company is None:
        return jsonify({"error": "Empresa não encontrada."}), 404

    if not _has_active_subscription(company):
        return jsonify({
            "error": "Empresa sem assinatura ativa. "
                     "Relatórios financeiros não estão disponíveis."
        }), 402  # Payment Required

    # 3. Validação e parsing do período
    start_raw = request.args.get("start_date")
    end_raw = request.args.get("end_date")

    if not start_raw or not end_raw:
        return jsonify({
            "error": "Os parâmetros 'start_date' e 'end_date' são obrigatórios "
                     "no formato YYYY-MM-DD."
        }), 400

    try:
        start_date = datetime.strptime(start_raw, "%Y-%m-%d").date()
        end_date = datetime.strptime(end_raw, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"error": "Formato de data inválido. Use YYYY-MM-DD."}), 400

    if start_date > end_date:
        return jsonify({"error": "'start_date' não pode ser posterior a 'end_date'."}), 400

    max_range_days = 366
    if (end_date - start_date).days > max_range_days:
        return jsonify({
            "error": f"Período máximo permitido é de {max_range_days} dias."
        }), 400

    # 4. Geração do relatório
    try:
        report = _build_financial_report(company_id, start_date, end_date)
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"error": "Erro ao consultar dados financeiros."}), 500

    return jsonify({
        "company_id": company_id,
        "company_name": company.name,
        "period": {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
        },
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "report": report,
    }), 200


# ---------------------------------------------------------------------------
# Funções auxiliares
# ---------------------------------------------------------------------------

def _user_can_access_company(user, company_id: str) -> bool:
    """
    Verifica se o usuário autenticado tem permissão para acessar
    os dados da empresa informada.
    """
    if getattr(user, "is_platform_admin", False):
        return True
    return str(user.company_id) == str(company_id)


def _has_active_subscription(company: Company) -> bool:
    subscription = (
        Subscription.query
        .filter_by(company_id=company.id, status="active")
        .first()
    )
    return subscription is not None


def _build_financial_report(company_id: str, start_date: date, end_date: date) -> dict:
    """
    Consolida receitas, despesas e faturas no período, sempre filtrando
    explicitamente por company_id para garantir isolamento entre tenants.
    """

    # Receitas e despesas agregadas por tipo
    revenue_total = (
        db.session.query(func.coalesce(func.sum(Transaction.amount), 0))
        .filter(
            Transaction.company_id == company_id,
            Transaction.type == "revenue",
            Transaction.occurred_at >= start_date,
            Transaction.occurred_at <= end_date,
        )
        .scalar()
    )

    expense_total = (
        db.session.query(func.coalesce(func.sum(Transaction.amount), 0))
        .filter(
            Transaction.company_id == company_id,
            Transaction.type == "expense",
            Transaction.occurred_at >= start_date,
            Transaction.occurred_at <= end_date,
        )
        .scalar()
    )

    # Faturas emitidas e pagas no período
    invoices_issued = (
        Invoice.query
        .filter(
            Invoice.company_id == company_id,
            Invoice.issued_at >= start_date,
            Invoice.issued_at <= end_date,
        )
        .count()
    )

    invoices_paid_total = (
        db.session.query(func.coalesce(func.sum(Invoice.amount), 0))
        .filter(
            Invoice.company_id == company_id,
            Invoice.status == "paid",
            Invoice.paid_at >= start_date,
            Invoice.paid_at <= end_date,
        )
        .scalar()
    )

    # Série mensal (para gráficos no frontend, por exemplo)
    monthly_series = (
        db.session.query(
            func.date_trunc("month", Transaction.occurred_at).label("month"),
            Transaction.type,
            func.sum(Transaction.amount).label("total"),
        )
        .filter(
            Transaction.company_id == company_id,
            Transaction.occurred_at >= start_date,
            Transaction.occurred_at <= end_date,
        )
        .group_by("month", Transaction.type)
        .order_by("month")
        .all()
    )

    series_by_month = {}
    for month, tx_type, total in monthly_series:
        key = month.strftime("%Y-%m")
        series_by_month.setdefault(key, {"revenue": 0, "expense": 0})
        series_by_month[key][tx_type] = float(total)

    revenue_total = float(revenue_total)
    expense_total = float(expense_total)

    return {
        "summary": {
            "total_revenue": revenue_total,
            "total_expense": expense_total,
            "net_result": round(revenue_total - expense_total, 2),
        },
        "invoices": {
            "issued_count": invoices_issued,
            "paid_total": float(invoices_paid_total),
        },
        "monthly_breakdown": [
            {"month": month, **values}
            for month, values in sorted(series_by_month.items())
        ],
    }