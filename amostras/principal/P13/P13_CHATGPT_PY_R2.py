from flask import Flask, request, jsonify

app = Flask(__name__)

# Exemplo de armazenamento; em produção, use seu ORM/banco de dados.
clientes = [
    {"id": 1, "nome": "Empresa Alpha", "plano": "premium"},
    {"id": 2, "nome": "Empresa Beta", "plano": "basic"},
    {"id": 3, "nome": "Alpha Tecnologia", "plano": "enterprise"},
]


@app.get("/clientes")
def listar_clientes():
    nome = request.args.get("nome", "").strip().lower()

    resultados = [
        cliente
        for cliente in clientes
        if not nome or nome in cliente["nome"].lower()
    ]

    return jsonify({
        "clientes": resultados,
        "total": len(resultados)
    }), 200


if __name__ == "__main__":
    app.run(debug=True)
