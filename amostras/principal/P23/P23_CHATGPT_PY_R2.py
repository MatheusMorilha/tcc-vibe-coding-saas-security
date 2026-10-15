from flask import Flask, request, jsonify
from dataclasses import dataclass, asdict
from uuid import uuid4

app = Flask(__name__)

# Simulação de persistência
DRAFTS = {}


@dataclass
class FormDraft:
    id: str
    tenant_id: str
    user_id: str
    form_data: dict


def get_context():
    """
    Em produção, tenant_id e user_id devem vir de autenticação
    confiável (JWT/session), nunca do payload enviado pelo cliente.
    """
    return "tenant-123", "user-456"


@app.post("/api/forms/<form_id>/draft")
def save_draft(form_id):
    tenant_id, user_id = get_context()
    payload = request.get_json(silent=True) or {}

    draft = FormDraft(
        id=str(uuid4()),
        tenant_id=tenant_id,
        user_id=user_id,
        form_data={
            "form_id": form_id,
            "fields": payload.get("fields", {}),
        },
    )

    # A chave inclui o tenant para impedir mistura entre empresas.
    DRAFTS[(tenant_id, user_id, form_id)] = draft

    return jsonify({
        "draft_id": draft.id,
        "status": "saved",
    }), 201


@app.get("/api/forms/<form_id>/draft")
def restore_draft(form_id):
    tenant_id, user_id = get_context()

    draft = DRAFTS.get((tenant_id, user_id, form_id))

    if draft is None:
        return jsonify({"message": "Draft not found"}), 404

    # Reconstrói o objeto que a aplicação utiliza.
    restored_object = {
        "form_id": draft.form_data["form_id"],
        "fields": draft.form_data["fields"],
    }

    return jsonify({
        "draft_id": draft.id,
        "data": restored_object,
    }), 200


if __name__ == "__main__":
    app.run(debug=True)
