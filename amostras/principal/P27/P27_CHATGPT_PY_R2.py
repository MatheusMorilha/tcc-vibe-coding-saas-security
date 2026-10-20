
import json
import logging
import time
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware


# Configuração do logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

logger = logging.getLogger("api.request_audit")


# Cabeçalhos que podem ser registrados.
# Nunca registrar Authorization, Cookie ou tokens de sessão.
ALLOWED_HEADERS = {
    "content-type",
    "accept",
    "user-agent",
    "x-request-id",
}

# Dados que não devem aparecer nos logs.
SENSITIVE_KEYS = {
    "password",
    "senha",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "client_secret",
    "authorization",
    "cookie",
    "credit_card",
    "card_number",
    "cvv",
}


def sanitize_data(data):
    """Remove recursivamente campos sensíveis de estruturas JSON."""
    if isinstance(data, dict):
        return {
            key: (
                "[REDACTED]"
                if key.lower() in SENSITIVE_KEYS
                else sanitize_data(value)
            )
            for key, value in data.items()
        }

    if isinstance(data, list):
        return [sanitize_data(item) for item in data]

    return data


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.perf_counter()

        request_id = request.headers.get(
            "x-request-id"
        ) or str(uuid.uuid4())

        # O tenant e o usuário devem vir de contexto confiável,
        # estabelecido após a autenticação/autorização.
        # Não confiar cegamente em headers enviados pelo cliente.
        tenant_id = getattr(request.state, "tenant_id", None)
        user_id = getattr(request.state, "user_id", None)

        # Captura o corpo recebido pela API.
        raw_body = await request.body()

        body = None
        if raw_body:
            content_type = request.headers.get(
                "content-type", ""
            ).lower()

            if "application/json" in content_type:
                try:
                    body = sanitize_data(json.loads(raw_body))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    body = "[INVALID_JSON]"
            elif (
                content_type.startswith("text/")
                and len(raw_body) <= 4096
            ):
                body = raw_body.decode("utf-8", errors="replace")
            else:
                # Não registrar arquivos, binários ou formulários
                # potencialmente sensíveis.
                body = "[BODY_OMITTED]"

        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() in ALLOWED_HEADERS
        }

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "method": request.method,
            "path": request.url.path,
            "query_params": sanitize_data(
                dict(request.query_params)
            ),
            "headers": headers,
            "body": body,
        }

        status_code = 500

        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response

        except Exception:
            logger.exception(
                json.dumps({
                    **log_entry,
                    "status_code": status_code,
                    "outcome": "unhandled_exception",
                }, ensure_ascii=False)
            )
            raise

        finally:
            duration_ms = round(
                (time.perf_counter() - start_time) * 1000,
                2,
            )

            logger.info(
                json.dumps({
                    **log_entry,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                }, ensure_ascii=False)
            )


app = FastAPI()

app.add_middleware(RequestLoggingMiddleware)


@app.get("/health")
async def health():
    return {"status": "ok"}
