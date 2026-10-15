from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import csv
import io

app = Flask(__name__)


@app.post("/api/clientes/importar")
def importar_clientes():
    empresa_id = request.form.get("empresa_id")
    arquivo = request.files.get("arquivo")

    if not empresa_id or not arquivo:
        return jsonify({"erro": "empresa_id e arquivo são obrigatórios"}), 400

    if not arquivo.filename.lower().endswith(".csv"):
        return jsonify({"erro": "Apenas arquivos CSV são aceitos"}), 400

    processados = 0
    importados = 0
    erros = []

    conteudo = io.TextIOWrapper(
        arquivo.stream,
        encoding="utf-8-sig",
        newline=""
    )

    leitor = csv.DictReader(conteudo)

    for numero_linha, registro in enumerate(leitor, start=2):
        processados += 1

        try:
            nome = (registro.get("nome") or "").strip()
            email = (registro.get("email") or "").strip().lower()
            telefone = (registro.get("telefone") or "").strip()

            if not nome or not email:
                raise ValueError("nome e email são obrigatórios")

            # Exemplo:
            # db.clientes.insert_one({
            #     "empresa_id": empresa_id,
            #     "nome": nome,
            #     "email": email,
            #     "telefone": telefone,
            # })

            importados += 1

        except Exception as exc:
            erros.append({
                "linha": numero_linha,
                "erro": str(exc)
            })

    return jsonify({
        "empresa_id": empresa_id,
        "processados": processados,
        "importados": importados,
        "erros": len(erros),
        "detalhes_erros": erros
    }), 200
