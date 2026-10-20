import json
import logging
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qs

from flask import Flask, request, g


app = Flask(__name__)

# Configuração do logger
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)

logger = logging.getLogger("api.audit")

MAX_BODY_SIZE = 64 * 1024  # 64 KB

SENSITIVE_FIELDS = {
    "password",
    "senha",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "secret",
    "api_key",
    "credit_card",
}


def redact_data(data):
    """Remove ou mascara campos sensíveis recursivamente."""
    if isinstance(data, dict):
        return {
            key: (
                "[REDACTED]"
                if key.lower() in SENSITIVE_FIELDS
                else redact_data(value)
            )
            for key, value in data.items()
        }

    if isinstance(data, list):
        return [redact_data(item) for item in data]

    return data


def get_request_body():
    """Obtém o corpo da requisição sem impedir sua leitura pelo Flask."""
    if request.content_length is None:
        return "[OMITTED: unknown body size]"

    if request.content_length > MAX_BODY_SIZE:
        return {
            "omitted": True,
            "reason": "body exceeds logging limit",
            "size_bytes": request.content_length,
        }

    raw_body = request.get_data(cache=True)

    if not raw_body:
        return None

    content_type = request.mimetype

    if content_type == "application/json":
        try:
            return redact_data(json.loads(raw_body))
        except (ValueError, UnicodeDecodeError):
            return "[INVALID JSON BODY]"

    if content_type == "application/x-www-form-urlencoded":
        fields = parse_qs(
            raw_body.decode("utf-8", errors="replace"),
            keep_blank_values=True,
        )
        return redact_data(fields)

    # Não registrar arquivos, conteúdo binário ou tipos desconhecidos.
    return {
        "omitted": True,
        "reason": "unsupported content type",
        "content_type": content_type,
        "size_bytes": len(raw_body),
    }


def safe_headers():
    """Registra somente cabeçalhos previamente permitidos."""
    allowed_headers = {
        "content-type",
        "accept",
        "user-agent",
        "x-request-id",
    }

    return {
        key.lower(): value
        for key, value in request.headers.items()
        if key.lower() in allowed_headers
    }


@app.before_request
def audit_request_start():
    g.request_id = request.headers.get(
        "X-Request-ID"
    ) or str(uuid.uuid4())

    g.request_started_at = time.monotonic()

    # Esses valores devem ser definidos pelo sistema de autenticação
    # e pela resolução confiável do tenant.
    g.tenant_id = request.environ.get("authenticated.tenant_id")
    g.user_id = request.environ.get("authenticated.user_id")

    g.audit_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": g.request_id,
        "tenant_id": g.tenant_id,
        "user_id": g.user_id,
        "method": request.method,
        "path": request.path,
        "query_params": redact_data(request.args.to_dict()),
        "headers": safe_headers(),
        "body": get_request_body(),
        "remote_addr": request.remote_addr,
    }


@app.after_request
def audit_request_end(response):
    started_at = getattr(g, "request_started_at", None)

    if started_at is None:
        return response

    log_data = getattr(g, "audit_data", {})

    log_data.update({
        "status_code": response.status_code,
        "duration_ms": round(
            (time.monotonic() - started_at) * 1000, 2
        ),
    })

    response.headers["X-Request-ID"] = g.request_id

    logger.info(json.dumps(
        log_data,
        ensure_ascii=False,
        default=str,
    ))

    return response


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    logger.exception(
        "Erro não tratado na API",
        extra={
            "request_id": getattr(g, "request_id", None),
            "tenant_id": getattr(g, "tenant_id", None),
        },
    )

    return {
        "error": "Internal server error",
        "request_id": getattr(g, "request_id", None),
    }, 500


if __name__ == "__main__":
    app.run(debug=False)