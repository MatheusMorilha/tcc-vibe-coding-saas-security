
import json
import logging
import time
import uuid
import re

from datetime import datetime, timezone
from urllib.parse import parse_qs
from wsgiref.util import request_uri


logger = logging.getLogger("saas.api.requests")

SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "credit_card",
    "card_number",
    "cpf",
}

MAX_BODY_SIZE = 64 * 1024  # 64 KB


def sanitize(value):
    """Mascara campos sensíveis em estruturas JSON ou dicionários."""
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if key.lower() in SENSITIVE_FIELDS
                else sanitize(item)
            )
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [sanitize(item) for item in value]

    return value


def sanitize_query_string(query_string):
    """Mascara parâmetros sensíveis da URL."""
    params = parse_qs(query_string, keep_blank_values=True)

    return sanitize(params)


class RequestLoggingMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        start_time = time.monotonic()
        request_id = str(uuid.uuid4())

        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")
        query_string = environ.get("QUERY_STRING", "")
        content_type = environ.get("CONTENT_TYPE", "")
        content_length = environ.get("CONTENT_LENGTH", "")

        # O middleware de autenticação deve preencher estes campos
        # somente após validar a identidade do usuário e do locatário.
        tenant_id = environ.get("saas.tenant_id")
        user_id = environ.get("saas.user_id")

        # Disponibiliza um identificador para rastreamento interno.
        environ["saas.request_id"] = request_id

        request_body = "[not captured]"
        body_size = 0

        try:
            size = int(content_length or 0)
        except (TypeError, ValueError):
            size = -1

        # Não registra corpos grandes, de tamanho desconhecido,
        # nem conteúdos binários ou multipartes.
        is_text_payload = (
            content_type.startswith("application/json")
            or content_type.startswith("text/")
            or content_type.startswith(
                "application/x-www-form-urlencoded"
            )
        )

        if 0 <= size <= MAX_BODY_SIZE and is_text_payload:
            raw_body = environ["wsgi.input"].read(size)
            body_size = len(raw_body)

            # Restaura o corpo para que a aplicação possa consumi-lo.
            from io import BytesIO
            environ["wsgi.input"] = BytesIO(raw_body)

            try:
                decoded = raw_body.decode("utf-8")

                if content_type.startswith("application/json"):
                    request_body = sanitize(json.loads(decoded))
                elif content_type.startswith(
                    "application/x-www-form-urlencoded"
                ):
                    request_body = sanitize(
                        parse_qs(decoded, keep_blank_values=True)
                    )
                else:
                    request_body = decoded

            except (UnicodeDecodeError, json.JSONDecodeError):
                request_body = "[unparseable payload]"
        elif size > MAX_BODY_SIZE:
            request_body = "[omitted: payload too large]"
        elif size < 0:
            request_body = "[omitted: unknown payload size]"
        elif not is_text_payload and size > 0:
            request_body = "[omitted: non-text payload]"

        # Registra apenas cabeçalhos selecionados, nunca todos.
        safe_headers = {
            "content_type": content_type,
            "content_length": content_length,
            "user_agent": environ.get("HTTP_USER_AGENT"),
            "origin": environ.get("HTTP_ORIGIN"),
        }

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "method": method,
            "path": path,
            "query_params": sanitize_query_string(query_string),
            "headers": safe_headers,
            "body": request_body,
            "body_size": body_size,
            "remote_addr": environ.get("REMOTE_ADDR"),
        }

        status_code = None

        def logging_start_response(status, headers, exc_info=None):
            nonlocal status_code
            status_code = int(status.split(" ", 1)[0])

            return start_response(status, headers, exc_info)

        try:
            response = self.app(environ, logging_start_response)
        except Exception:
            event["status_code"] = 500
            event["duration_ms"] = round(
                (time.monotonic() - start_time) * 1000, 2
            )
            event["error"] = "Unhandled application exception"
            logger.exception(
                json.dumps(event, ensure_ascii=False, default=str)
            )
            raise

        def logged_response():
            try:
                for chunk in response:
                    yield chunk
            finally:
                close = getattr(response, "close", None)
                if close:
                    close()

                event["status_code"] = status_code
                event["duration_ms"] = round(
                    (time.monotonic() - start_time) * 1000, 2
                )

                logger.info(
                    json.dumps(event, ensure_ascii=False, default=str)
                )

        return logged_response()
