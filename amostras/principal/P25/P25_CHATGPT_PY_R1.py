
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


# Configuração do logger de auditoria
logger = logging.getLogger("security.authentication")
logger.setLevel(logging.INFO)

handler = logging.FileHandler(
    "authentication_audit.log",
    encoding="utf-8"
)

handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)


class AuthenticationAuditMiddleware(BaseHTTPMiddleware):
    """
    Registra tentativas malsucedidas de autenticação.
    Segredos e credenciais sensíveis são removidos antes do log.
    """

    AUTH_PATHS = {"/auth/login", "/api/auth/login"}

    SENSITIVE_FIELDS = {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "set-cookie",
        "client_secret",
        "api_key",
        "private_key",
        "credit_card",
    }

    MAX_BODY_SIZE = 16_384

    def sanitize(self, data: Any) -> Any:
        """Remove campos sensíveis recursivamente."""
        if isinstance(data, dict):
            sanitized = {}

            for key, value in data.items():
                normalized_key = re.sub(
                    r"[^a-z0-9_]",
                    "",
                    str(key).lower()
                )

                if (
                    normalized_key in self.SENSITIVE_FIELDS
                    or any(
                        normalized_key.endswith("_" + field)
                        for field in (
                            "password",
                            "token",
                            "secret",
                        )
                    )
                ):
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = self.sanitize(value)

            return sanitized

        if isinstance(data, list):
            return [self.sanitize(item) for item in data]

        if isinstance(data, str):
            return data[:1000]

        if isinstance(data, (int, float, bool)) or data is None:
            return data

        return "[UNSUPPORTED_VALUE]"

    async def dispatch(
        self,
        request: Request,
        call_next
    ) -> Response:

        # Não auditar rotas que não sejam de autenticação.
        if (
            request.url.path not in self.AUTH_PATHS
            or request.method != "POST"
        ):
            return await call_next(request)

        body_for_log = {
            "payload": "[NOT_CAPTURED]"
        }

        content_length = request.headers.get("content-length")

        # Limita a coleta para evitar logs excessivos.
        try:
            if (
                content_length is not None
                and int(content_length) > self.MAX_BODY_SIZE
            ):
                body_for_log = {
                    "payload": "[BODY_TOO_LARGE]"
                }
            else:
                raw_body = await request.body()

                if len(raw_body) > self.MAX_BODY_SIZE:
                    body_for_log = {
                        "payload": "[BODY_TOO_LARGE]"
                    }
                elif raw_body:
                    content_type = request.headers.get(
                        "content-type", ""
                    )

                    if "application/json" in content_type.lower():
                        try:
                            parsed = json.loads(raw_body)
                            body_for_log = self.sanitize(parsed)
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            body_for_log = {
                                "payload": "[INVALID_JSON]"
                            }
                    else:
                        # Não registrar formatos desconhecidos
                        # ou conteúdo potencialmente sensível.
                        body_for_log = {
                            "payload": "[UNSUPPORTED_CONTENT_TYPE]"
                        }
                else:
                    body_for_log = {}

        except (ValueError, UnicodeDecodeError):
            body_for_log = {"payload": "[BODY_UNAVAILABLE]"}

        # Executa a autenticação normalmente.
        response = await call_next(request)

        # Só registra respostas indicativas de falha de autenticação.
        if response.status_code in (401, 403):
            client_ip = (
                request.client.host
                if request.client is not None
                else "unknown"
            )

            # O tenant_id do corpo é apenas uma alegação do cliente.
            requested_tenant_id = (
                body_for_log.get("tenant_id")
                if isinstance(body_for_log, dict)
                else None
            )

            audit_event = {
                "event": "authentication_failure",
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "client_ip": client_ip,
                "user_agent": request.headers.get(
                    "user-agent", "unknown"
                )[:500],
                "requested_tenant_id": requested_tenant_id,
                "request_payload": body_for_log,
            }

            logger.warning(
                json.dumps(
                    audit_event,
                    ensure_ascii=False,
                    default=str
                )
            )

        return response


app = FastAPI()

app.add_middleware(AuthenticationAuditMiddleware)


@app.post("/auth/login")
async def login(request: Request):
    # Substitua por sua lógica real de autenticação.
    return {"message": "Endpoint de autenticação"}
