"""
request_logging.py
Middleware ASGI de log de requisições para plataforma SaaS multilocatária.
"""
import json
import logging
import re
import time
import uuid
from typing import Any, Iterable
from urllib.parse import parse_qsl

logger = logging.getLogger("api.requests")

# Fragmentos (normalizados: minúsculos, só alfanuméricos) que marcam um campo como sensível.
DEFAULT_SENSITIVE_FRAGMENTS = (
    "password", "passwd", "senha", "token", "secret", "apikey",
    "authorization", "cookie", "cvv", "cvc", "creditcard", "cartao",
    "cardnumber", "privatekey", "credential", "cpf",
)

SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token",
}

REDACTED = "***REDACTED***"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_NON_ALNUM = re.compile(r"[^a-z0-9]")


class RequestLoggingMiddleware:
    def __init__(
        self,
        app,
        max_body_bytes: int = 64 * 1024,
        extra_sensitive_fragments: Iterable[str] = (),
        skip_paths: Iterable[str] = ("/health", "/healthz", "/metrics"),
        max_depth: int = 20,
    ):
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.sensitive = tuple(DEFAULT_SENSITIVE_FRAGMENTS) + tuple(
            _NON_ALNUM.sub("", f.lower()) for f in extra_sensitive_fragments
        )
        self.skip_paths = set(skip_paths)
        self.max_depth = max_depth

    # ------------------------------------------------------------------ ASGI
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] in self.skip_paths:
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }

        request_id = headers.get("x-request-id", "")
        if not _REQUEST_ID_RE.match(request_id):
            request_id = uuid.uuid4().hex

        # Disponibiliza o request_id para o restante da aplicação.
        state = scope.setdefault("state", {})
        if isinstance(state, dict):
            state["request_id"] = request_id

        content_type = headers.get("content-type", "").split(";")[0].strip().lower()
        capture_body = content_type == "application/json" or \
            content_type == "application/x-www-form-urlencoded"

        chunks: list[bytes] = []
        body_size = 0
        truncated = False
        status_code = None

        async def receive_wrapper():
            nonlocal body_size, truncated
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"") or b""
                body_size += len(chunk)
                if capture_body and not truncated:
                    if body_size > self.max_body_bytes:
                        truncated = True
                        chunks.clear()  # libera memória; corpo grande não é armazenado
                    else:
                        chunks.append(chunk)
            return message

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                resp_headers = list(message.get("headers", []))
                resp_headers.append((b"x-request-id", request_id.encode()))
                message = {**message, "headers": resp_headers}
            await send(message)

        error_name = None
        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except Exception as exc:  # registra e propaga
            error_name = type(exc).__name__
            if status_code is None:
                status_code = 500
            raise
        finally:
            try:
                self._emit(
                    scope, headers, content_type, capture_body, chunks,
                    body_size, truncated, status_code, error_name,
                    request_id, started,
                )
            except Exception:
                logger.exception("Falha ao registrar log da requisição")

    # --------------------------------------------------------------- Registro
    def _emit(self, scope, headers, content_type, capture_body, chunks,
              body_size, truncated, status_code, error_name, request_id, started):
        state = scope.get("state") or {}
        get = state.get if isinstance(state, dict) else (lambda k, d=None: getattr(state, k, d))

        client = scope.get("client")
        record = {
            "event": "http_request",
            "request_id": request_id,
            # Preenchidos pelo middleware/dependência de autenticação.
            "tenant_id": get("tenant_id"),
            "user_id": get("user_id"),
            "method": scope["method"],
            "path": scope["path"],
            "query": self._redact_pairs(
                parse_qsl(scope.get("query_string", b"").decode("latin-1"),
                          keep_blank_values=True)
            ),
            "headers": {
                k: (REDACTED if k in SENSITIVE_HEADERS else v)
                for k, v in headers.items()
            },
            "client_ip": client[0] if client else None,
            "content_type": content_type or None,
            "body_size": body_size,
            "body": self._body_payload(content_type, capture_body, chunks, truncated),
            "status_code": status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }
        if error_name:
            record["error"] = error_name

        level = logging.ERROR if (status_code or 0) >= 500 else logging.INFO
        logger.log(level, json.dumps(record, ensure_ascii=False, default=str))

    def _body_payload(self, content_type, capture_body, chunks, truncated):
        if not capture_body:
            return {"captured": False, "reason": "tipo de conteúdo não registrado"}
        if truncated:
            return {"captured": False, "reason": f"corpo acima de {self.max_body_bytes} bytes"}
        raw = b"".join(chunks)
        if not raw:
            return None
        try:
            text = raw.decode("utf-8")
            if content_type == "application/json":
                return self._redact(json.loads(text), 0)
            return self._redact_pairs(parse_qsl(text, keep_blank_values=True))
        except (UnicodeDecodeError, ValueError):
            # Corpo malformado: útil para o suporte saber, mas não gravamos o conteúdo bruto.
            return {"captured": False, "reason": "corpo inválido para o tipo declarado",
                    "size": len(raw)}

    # ---------------------------------------------------------- Mascaramento
    def _is_sensitive(self, key: Any) -> bool:
        norm = _NON_ALNUM.sub("", str(key).lower())
        return any(frag in norm for frag in self.sensitive)

    def _redact(self, value: Any, depth: int) -> Any:
        if depth > self.max_depth:
            return "***MAX_DEPTH***"
        if isinstance(value, dict):
            return {
                k: (REDACTED if self._is_sensitive(k) else self._redact(v, depth + 1))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self._redact(v, depth + 1) for v in value]
        return value

    def _redact_pairs(self, pairs):
        out: dict[str, Any] = {}
        for k, v in pairs:
            v = REDACTED if self._is_sensitive(k) else v
            if k in out:  # parâmetro repetido
                out[k] = (out[k] if isinstance(out[k], list) else [out[k]]) + [v]
            else:
                out[k] = v
        return out