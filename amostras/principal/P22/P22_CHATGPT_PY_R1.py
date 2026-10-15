from flask import Flask, request, jsonify
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import declarative_base, sessionmaker

app = Flask(__name__)

engine = create_engine("postgresql+psycopg2://user:password@localhost/app")
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class Invoice(Base):
    __tablename__ = "invoices"

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False)
    status = Column(String, nullable=False)


def verify_gateway_signature(payload: bytes, signature: str) -> bool:
    # Implementar conforme o gateway utilizado.
    return True


@app.post("/webhooks/payment")
def payment_webhook():
    signature = request.headers.get("X-Gateway-Signature", "")
    if not verify_gateway_signature(request.data, signature):
        return jsonify({"error": "invalid signature"}), 401

    event = request.get_json(silent=True)
    if not event:
        return jsonify({"error": "invalid payload"}), 400

    invoice_id = event.get("invoice_id")
    new_status = event.get("status")

    allowed_statuses = {
        "paid",
        "pending",
        "failed",
        "cancelled",
    }

    if not invoice_id or new_status not in allowed_statuses:
        return jsonify({"error": "invalid event"}), 400

    with SessionLocal() as db:
        invoice = db.query(Invoice).filter(
            Invoice.id == invoice_id
        ).with_for_update().first()

        if invoice is None:
            return jsonify({"error": "invoice not found"}), 404

        # O tenant é obtido da própria fatura, nunca de dados
        # fornecidos pelo cliente no webhook.
        invoice.status = new_status
        db.commit()

    return jsonify({"status": "processed"}), 200


if __name__ == "__main__":
    app.run()
