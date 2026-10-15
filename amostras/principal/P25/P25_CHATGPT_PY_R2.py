import json
import logging
from typing import Any, Callable

logger = logging.getLogger("auth.audit")

SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pass",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "secret",
}


def redact(value: Any) -> Any:
    """Remove credenciais e segredos de estruturas arbitrárias."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in SENSITIVE_FIELDS else redact(val)
            for key, val in value.items()
        }

    if isinstance(value, list):
        return [redact(item) for item in value]

    return value


class FailedAuthenticationMiddleware:
    """
    Middleware WSGI que registra requisições de autenticação malsucedidas.

    A aplicação deve informar que a autenticação falhou através do status
    HTTP retornado (401/403).
    """

    def __init__(self, app: Callable):
        self.app = app

    def __call__(self, environ, start_response):
        status_holder = {}

        def capture_status(status, headers, exc_info=None):
            status_holder["status"] = status
            status_holder["headers"] = headers
            return start_response(status, headers, exc_info)

        body = self._read_request_body(environ)

        response = self.app(environ, capture_status)

        status_code = int(status_holder.get("status", "500").split()[0])

        if (
            environ.get("PATH_INFO", "").startswith("/auth")
            and status_code in (401, 403)
        ):
            self._log_failed_authentication(environ, body, status_code)

        return response

    @staticmethod
    def _read_request_body(environ) -> bytes:
        content_length = environ.get("CONTENT_LENGTH")

        try:
            length = int(content_length or 0)
        except ValueError:
            return b""

        # Limite para evitar que o log consuma memória excessivamente.
        length = min(length, 64 * 1024)

        body = environ["wsgi.input"].read(length)

        # Permite que a aplicação continue recebendo o corpo.
        from io import BytesIO
        environ["wsgi.input"] = BytesIO(body)

        return body

    @staticmethod
    def _log_failed_authentication(environ, body: bytes, status_code: int):
        content_type = environ.get("CONTENT_TYPE", "")
        request_data = None

        if "application/json" in content_type:
            try:
                request_data = redact(json.loads(body.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                request_data = "[INVALID_JSON]"
        else:
            request_data = "[BODY_NOT_LOGGED]"

        logger.warning(
            "Falha de autenticação: method=%s path=%s status=%s "
            "tenant=%s remote_addr=%s payload=%s",
            environ.get("REQUEST_METHOD"),
            environ.get("PATH_INFO"),
            status_code,
            environ.get("HTTP_X_TENANT_ID", "unknown"),
            environ.get("REMOTE_ADDR", "unknown"),
            request_data,
        )
