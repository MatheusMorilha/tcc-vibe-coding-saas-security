import json
import logging
import time
import uuid
from typing import Any, Callable, Dict, Iterable, List, Optional


logger = logging.getLogger("api.request")


SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
}

SENSITIVE_FIELDS = {
    "password",
    "current_password",
    "new_password",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "client_secret",
}


def mask_sensitive_data(value: Any) -> Any:
    """Remove dados sensíveis de estruturas JSON."""
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if key.lower() in SENSITIVE_FIELDS
                else mask_sensitive_data(item)
            )
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [mask_sensitive_data(item) for item in value]

    return value


def sanitize_headers(headers: Iterable[tuple[bytes, bytes]]) -> Dict[str, str]:
    """Converte headers para dict e mascara credenciais."""
    result = {}

    for raw_name, raw_value in headers:
        name = raw_name.decode("latin-1")
        value = raw_value.decode("latin-1")

        if name.lower() in SENSITIVE_HEADERS:
            value = "[REDACTED]"

        result[name] = value

    return result


class RequestLoggingMiddleware:
    def __init__(
        self,
        app: Callable,
        max_body_size: int = 1024 * 1024,
    ):
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = str(uuid.uuid4())
        started_at = time.perf_counter()

        method = scope.get("method", "")
        path = scope.get("path", "")
        query_string = scope.get("query_string", b"").decode("utf-8", "replace")

        headers = sanitize_headers(scope.get("headers", []))

        # IDs importantes para uma aplicação SaaS multilocatária.
        tenant_id = headers.get("X-Tenant-ID")
        user_id = headers.get("X-User-ID")

        body_chunks: List[bytes] = []
        body_size = 0

        async def receive_wrapper():
            nonlocal body_size

            message = await receive()

            if message["type"] == "http.request":
                body = message.get("body", b"")

                if body and body_size < self.max_body_size:
                    remaining = self.max_body_size - body_size
                    body_chunks.append(body[:remaining])
                    body_size += min(len(body), remaining)

            return message

        status_code: Optional[int] = None

        async def send_wrapper(message):
            nonlocal status_code

            if message["type"] == "http.response.start":
                status_code = message["status"]

            await send(message)

        try:
            await self.app(scope, receive_wrapper, send_wrapper)

        finally:
            elapsed_ms = round(
                (time.perf_counter() - started_at) * 1000,
                2,
            )

            body = b"".join(body_chunks)

            request_body: Any

            if not body:
                request_body = None

            elif len(body) >= self.max_body_size:
                request_body = {
                    "_truncated": True,
                    "_max_bytes": self.max_body_size,
                }

            else:
                content_type = headers.get("content-type", "").lower()

                if "application/json" in content_type:
                    try:
                        request_body = mask_sensitive_data(
                            json.loads(body.decode("utf-8"))
                        )
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        request_body = "[INVALID_JSON]"

                elif (
                    content_type.startswith("text/")
                    or "application/xml" in content_type
                ):
                    try:
                        request_body = body.decode("utf-8", "replace")
                    except UnicodeDecodeError:
                        request_body = "[UNREADABLE_BODY]"

                else:
                    request_body = {
                        "_binary_body": True,
                        "_bytes": len(body),
                    }

            log_data = {
                "event": "http_request",
                "request_id": request_id,
                "timestamp": time.time(),
                "method": method,
                "path": path,
                "query_string": query_string,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "headers": headers,
                "body": request_body,
                "status_code": status_code,
                "duration_ms": elapsed_ms,
            }

            logger.info(
                "API request: %s",
                json.dumps(
                    log_data,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            )
