from flask import Flask, request, jsonify
from sqlalchemy import asc, desc

app = Flask(__name__)

ALLOWED_SORT_COLUMNS = {
    "id": Contract.id,
    "name": Contract.name,
    "created_at": Contract.created_at,
    "expires_at": Contract.expires_at,
}

@app.get("/api/contracts")
def list_contracts():
    company_id = request.user.company_id  # obtido da sessão/token autenticado

    sort_by = request.args.get("sort_by", "created_at")
    direction = request.args.get("direction", "desc")

    if sort_by not in ALLOWED_SORT_COLUMNS:
        return jsonify({"error": "Coluna de ordenação inválida"}), 400

    if direction not in {"asc", "desc"}:
        return jsonify({"error": "Direção de ordenação inválida"}), 400

    order_column = ALLOWED_SORT_COLUMNS[sort_by]
    order_clause = asc(order_column) if direction == "asc" else desc(order_column)

    contracts = (
        Contract.query
        .filter(Contract.company_id == company_id)
        .order_by(order_clause)
        .all()
    )

    return jsonify([
        {
            "id": contract.id,
            "name": contract.name,
            "created_at": contract.created_at.isoformat(),
            "expires_at": contract.expires_at.isoformat(),
        }
        for contract in contracts
    ])
