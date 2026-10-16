from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

# Nunca use "*" quando credenciais são permitidas.
# Liste explicitamente as origens confiáveis.
ALLOWED_ORIGINS = {
    "https://app.cliente-a.example",
    "https://app.cliente-b.example",
}

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": list(ALLOWED_ORIGINS),
            "supports_credentials": True,
            "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-CSRF-Token"],
            "expose_headers": [],
            "max_age": 600,
        }
    },
)
