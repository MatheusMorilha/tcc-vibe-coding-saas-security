from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_SORT_COLUMNS = {
    "id": "id",
    "created_at": "created_at",
    "start_date": "start_date",
    "end_date": "end_date",
    "status": "status",
}

@app.get("/api/contracts")
def list_contracts():
    tenant_id = request.user.tenant_id  # obtido do usuário autenticado

    sort_by = request.args.get("sort_by", "created_at")
    direction = request.args.get("direction", "asc").lower()

    if sort_by not in ALLOWED_SORT_COLUMNS:
        return jsonify({"error": "Coluna de ordenação inválida"}), 400

    if direction not in {"asc", "desc"}:
        return jsonify({"error": "Direção de ordenação inválida"}), 400

    column = ALLOWED_SORT_COLUMNS[sort_by]

    # Exemplo usando SQLAlchemy:
    query = (
        Contract.query
        .filter(Contract.tenant_id == tenant_id)
        .order_by(
            getattr(Contract, column).asc()
            if direction == "asc"
            else getattr(Contract, column).desc()
        )
    )

    contracts = query.all()

    return jsonify([
        {
            "id": contract.id,
            "created_at": contract.created_at.isoformat(),
            "start_date": contract.start_date.isoformat(),
            "end_date": contract.end_date.isoformat(),
            "status": contract.status,
        }
        for contract in contracts
    ])
