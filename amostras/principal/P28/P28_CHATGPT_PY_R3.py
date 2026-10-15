import requests
from functools import wraps
from flask import request, jsonify, g

BILLING_URL = "https://billing.example.com/api/subscriptions"


def require_active_subscription(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        company_id = g.company_id  # definido previamente pelo middleware de autenticação

        try:
            response = requests.get(
                f"{BILLING_URL}/{company_id}",
                timeout=3,
            )
            response.raise_for_status()
            subscription = response.json()
        except requests.RequestException:
            return jsonify({"error": "Serviço de faturamento indisponível"}), 503

        if subscription.get("status") != "active":
            return jsonify({"error": "Assinatura inativa"}), 403

        return view(*args, **kwargs)

    return wrapper
