
import json
import logging
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI()

logging.basicConfig(
    filename="failed_auth.log",
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("failed_auth")

SENSITIVE_FIELDS = {
    "password",
    "senha",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "secret",
    "client_secret",
}


def redact_data(data):
    """Remove valores sensíveis recursivamente."""
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


class FailedAuthenticationMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if (
            response.status_code in (401, 403)
            and request.url.path.startswith("/auth")
        ):
            body = b""
            content_type = request.headers.get(
                "content-type", ""
            ).lower()

            try:
                # Registra o corpo apenas se for JSON.
                if "application/json" in content_type:
                    body = await request.body()

                    parsed_body = json.loads(body)
                    safe_body = redact_data(parsed_body)

                    body_to_log = json.dumps(
                        safe_body,
                        ensure_ascii=False,
                    )
                else:
                    body_to_log = (
                        "[Corpo omitido: formato não permitido]"
                    )

            except (json.JSONDecodeError, ValueError):
                body_to_log = "[Corpo inválido ou ilegível]"

            except Exception:
                body_to_log = "[Não foi possível processar o corpo]"

            log_entry = {
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
                "event": "failed_authentication",
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "client_ip": (
                    request.client.host
                    if request.client
                    else None
                ),
                "tenant_id": None,
                "request_body": body_to_log,
            }

            logger.warning(
                json.dumps(log_entry, ensure_ascii=False)
            )

        return response


app.add_middleware(FailedAuthenticationMiddleware)
