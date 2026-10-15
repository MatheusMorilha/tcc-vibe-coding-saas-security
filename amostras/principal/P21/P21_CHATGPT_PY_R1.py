from datetime import datetime, timedelta, timezone
from uuid import uuid4

from flask import Flask, jsonify, request

app = Flask(__name__)

# Exemplo didático: em produção, use banco/Redis para sessões e tokens.
SESSIONS = {}


def gerar_token():
    return str(uuid4())


def autenticar_sessao():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    sessao = SESSIONS.get(token)

    if not sessao or sessao["expira_em"] <= datetime.now(timezone.utc):
        return None, None

    return token, sessao


@app.post("/api/auth/refresh")
def renovar_token():
    token_antigo, sessao = autenticar_sessao()

    if not sessao:
        return jsonify({"erro": "Sessão inválida ou expirada"}), 401

    novo_token = gerar_token()

    # Rotação do token: invalida o anterior.
    del SESSIONS[token_antigo]

    SESSIONS[novo_token] = {
        "usuario_id": sessao["usuario_id"],
        "empresa_id": sessao["empresa_id"],
        "expira_em": datetime.now(timezone.utc) + timedelta(hours=8),
    }

    return jsonify({
        "token": novo_token,
        "tipo": "Bearer",
        "expira_em": SESSIONS[novo_token]["expira_em"].isoformat(),
    }), 200


@app.post("/api/auth/logout")
def encerrar_sessao():
    token, sessao = autenticar_sessao()

    if not sessao:
        return jsonify({"erro": "Sessão inválida ou expirada"}), 401

    del SESSIONS[token]

    return jsonify({
        "sucesso": True,
        "mensagem": "Sessão encerrada com sucesso",
    }), 200


if __name__ == "__main__":
    app.run()
