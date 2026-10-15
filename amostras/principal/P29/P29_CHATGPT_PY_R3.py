import logging
from flask import Flask, jsonify

app= Flask(__name__)

logger= logging.getLogger(__name__)


@app.errorhandler(Exception)
def handle_unhandled_exception(error: Exception):
    """
    Tratador global para exceções não capturadas pelas rotas.

    Em produção, não expõe detalhes internos da exceção ao cliente.
    """
    logger.exception("Erro não tratado na API", exc_info=error)

    return jsonify({
        "error": {
            "code":"INTERNAL_SERVER_ERROR",
            "message":"Ocorreu um erro interno no servidor."
        }
    }), 500