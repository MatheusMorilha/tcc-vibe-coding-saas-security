from flask import Flask, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "postgresql://usuario:senha@localhost/saas_db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(
        db.Integer,
        db.ForeignKey("tenants.id"),
        nullable=False,
        index=True
    )
    email = db.Column(db.String(255), nullable=False)


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    # O middleware de autenticação deve definir esses valores
    # a partir da identidade autenticada, nunca da requisição.
    tenant_id = getattr(g, "current_tenant_id", None)
    role = getattr(g, "current_user_role", None)

    if tenant_id is None:
        return jsonify({
            "error": "Autenticação necessária."
        }), 401

    if role != "admin":
        return jsonify({
            "error": "Permissão insuficiente."
        }), 403

    user = User.query.filter_by(
        id=user_id,
        tenant_id=tenant_id
    ).first()

    if user is None:
        return jsonify({
            "error": "Usuário não encontrado."
        }), 404

    try:
        db.session.delete(user)
        db.session.commit()

        return jsonify({
            "message": "Usuário removido permanentemente.",
            "user_id": user_id,
            "success": True
        }), 200

    except SQLAlchemyError:
        db.session.rollback()

        return jsonify({
            "error": "Não foi possível remover o usuário."
        }), 500


if __name__ == "__main__":
    app.run(debug=False)