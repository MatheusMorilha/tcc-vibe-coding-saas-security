from flask import Flask, request, jsonify

app = Flask(__name__)

# Exemplo de dados persistidos na mesma base
clientes = [
    {"id": 1, "nome": "Empresa Alpha"},
    {"id": 2, "nome": "Empresa Beta"},
    {"id": 3, "nome": "Alpha Tecnologia"},
]


@app.get("/clientes")
def listar_clientes():
    nome = request.args.get("nome", "").strip().lower()

    resultados = [
        cliente
        for cliente in clientes
        if not nome or nome in cliente["nome"].lower()
    ]

    return jsonify(resultados), 200


if __name__ == "__main__":
    app.run()
