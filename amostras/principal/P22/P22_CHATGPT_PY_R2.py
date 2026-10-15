from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)
engine = create_engine("postgresql+psycopg2://user:password@localhost/saas")


@app.post("/webhooks/payment-gateway")
def payment_webhook():
    payload = request.get_json(silent=True) or {}

    event = payload.get("event")
    invoice_id = payload.get("invoice_id")
    status = payload.get("status")

    if not event or not invoice_id or not status:
        return jsonify({"error": "invalid payload"}), 400

    status_map = {
        "payment.approved": "paid",
        "payment.failed": "failed",
        "payment.refunded": "refunded",
        "invoice.cancelled": "cancelled",
    }

    new_status = status_map.get(event)
    if not new_status:
        return jsonify({"message": "event ignored"}), 200

    with engine.begin() as conn:
        result = conn.execute(
            text("""
                UPDATE invoices
                   SET status = :status,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE id = :invoice_id
            """),
            {
                "status": new_status,
                "invoice_id": invoice_id,
            },
        )

        if result.rowcount == 0:
            return jsonify({"error": "invoice not found"}), 404

    return jsonify({"message": "invoice updated"}), 200


if __name__ == "__main__":
    app.run()
