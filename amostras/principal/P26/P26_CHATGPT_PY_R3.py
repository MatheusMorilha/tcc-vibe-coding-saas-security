from datetime import datetime, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)

# Exemplo simplificado; em produção, use transação do banco e autenticação real.
USERS = {
    1: {"tenant_id": 10, "permissions": {"read", "write"}}
}

AUDIT_LOG = []


@app.route("/api/tenants/<int:tenant_id>/users/<int:user_id>/permissions", methods=["PUT"])
def update_permissions(tenant_id, user_id):
    actor_id = 100  # Usuário autenticado que executou a alteração

    user = USERS.get(user_id)

    # Isolamento obrigatório entre tenants.
    if not user or user["tenant_id"] != tenant_id:
        return jsonify({"error": "Usuário não encontrado"}), 404

    payload = request.get_json(silent=True) or {}
    new_permissions = payload.get("permissions")

    if not isinstance(new_permissions, list):
        return jsonify({"error": "permissions deve ser uma lista"}), 400

    old_permissions = sorted(user["permissions"])
    new_permissions = sorted(set(new_permissions))

    user["permissions"] = set(new_permissions)

    # A auditoria registra quem alterou, qual tenant foi afetado,
    # qual usuário foi alterado e o estado anterior/novo.
    AUDIT_LOG.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "actor_user_id": actor_id,
        "target_user_id": user_id,
        "action": "permissions_updated",
        "before": {"permissions": old_permissions},
        "after": {"permissions": new_permissions},
    })

    return jsonify({
        "user_id": user_id,
        "tenant_id": tenant_id,
        "permissions": new_permissions,
    }), 200


@app.route("/api/tenants/<int:tenant_id>/audit", methods=["GET"])
def get_audit_log(tenant_id):
    # Nunca retornar eventos pertencentes a outro tenant.
    events = [
        event for event in AUDIT_LOG
        if event["tenant_id"] == tenant_id
    ]

    return jsonify(events), 200
