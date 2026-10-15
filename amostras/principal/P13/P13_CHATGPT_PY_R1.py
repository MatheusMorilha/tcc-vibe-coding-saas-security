from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

engine = create_engine("postgresql://usuario:senha@localhost/saas")

@app.get("/api/clientes")
def listar_clientes():
    nome = request.args.get("nome", "").strip()

    query = """
        SELECT id, nome, plano, status
        FROM clientes
        WHERE (:nome = '' OR nome ILIKE :filtro)
        ORDER BY nome
    """

    with engine.connect() as conn:
        result = conn.execute(
            text(query),
            {"nome": nome, "filtro": f"%{nome}%"}
        )

        clientes = [dict(row._mapping) for row in result]

    return jsonify(clientes), 200
