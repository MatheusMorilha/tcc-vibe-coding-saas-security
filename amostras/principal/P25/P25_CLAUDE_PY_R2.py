"""
auth_failure_log.py
Middleware ASGI que registra tentativas de autenticação malsucedidas.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Iterable, Optional, Protocol
from urllib.parse import parse_qsl

REDACTED = "[REDACTED]"

# Fragmentos que, se presentes no nome de um campo, indicam dado sensível.
SENSITIVE_FRAGMENTS = (
    "password", "passwd", "senha", "secret", "token", "authorization",
    "api_key", "apikey", "otp", "pin", "cvv", "cartao", "card_number",
    "credential", "assertion", "signature",
)

# Headers que podem ser registrados (allowlist).
SAFE_HEADERS = (
    "user-agent", "content-type", "content-length", "accept",
    "accept-language", "origin", "referer", "host",
    "x-request-id", "x-tenant-id", "x-forwarded-for", "x-real-ip",
)

MAX_STR_LEN = 256
MAX_LIST_ITEMS = 50
MAX_DEPTH = 6

_log = logging.getLogger("security.auth_failures")


# --------------------------------------------------------------------------
# Sinks (destino dos registros)
# --------------------------------------------------------------------------
class AuthFailureSink(Protocol):
    async def write(self, record: dict[str, Any]) -> None: ...


class LoggingSink:
    """Grava cada registro como uma linha JSON no logger dedicado."""

    def __init__(self, logger: logging.Logger = _log) -> None:
        self._logger = logger

    async def write(self, record: dict[str, Any]) -> None:
        # json.dumps escapa \n e \r, impedindo injeção de linhas falsas no log.
        self._logger.warning(json.dumps(record, ensure_ascii=False, default=str))


# --------------------------------------------------------------------------
# Sanitização
# --------------------------------------------------------------------------
def _is_sensitive(key: str) -> bool:
    k = key.lower()
    return any(fragment in k for fragment in SENSITIVE_FRAGMENTS)


def _redact(value: Any, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {
            str(k): REDACTED if _is_sensitive(str(k)) else _redact(v, depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v, depth + 1) for v in value[:MAX_LIST_ITEMS]]
    if isinstance(value, str):
        return value if len(value) <= MAX_STR_LEN else value[:MAX_STR_LEN] + "…[TRUNCATED]"
    return value


def _sanitize_headers(raw_headers: Iterable[tuple[bytes, bytes]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name_b, value_b in raw_headers:
        name = name_b.decode("latin-1").lower()
        value = value_b.decode("latin-1")
        if name in SAFE_HEADERS:
            out[name] = value[:MAX_STR_LEN]
        elif name == "authorization":
            scheme, _, cred = value.partition(" ")
            out[name] = {"scheme": scheme[:32], "credential_length": len(cred)}
        elif name == "cookie":
            out["cookie_present"] = True
    return out


def _sanitize_query(query_string: bytes) -> dict[str, Any]:
    pairs = parse_qsl(query_string.decode("utf-8", "replace"), keep_blank_values=True)
    return _redact(dict(pairs))


def _sanitize_body(body: bytes, content_type: str) -> dict[str, Any]:
    """Retorna uma representação segura do corpo; nunca o corpo bruto."""
    info: dict[str, Any] = {"size_bytes": len(body)}
    if not body:
        return info

    ctype = content_type.split(";")[0].strip().lower()
    text = body.decode("utf-8", "replace")
    try:
        if ctype == "application/json" or ctype.endswith("+json"):
            info["json"] = _redact(json.loads(text))
        elif ctype == "application/x-www-form-urlencoded":
            info["form"] = _redact(dict(parse_qsl(text, keep_blank_values=True)))
        else:
            info["note"] = f"conteúdo '{ctype or 'desconhecido'}' não registrado"
    except ValueError:
        info["note"] = "corpo malformado; conteúdo não registrado"
    return info


# --------------------------------------------------------------------------
# Middleware
# --------------------------------------------------------------------------
TenantResolver = Callable[[dict[str, Any]], Optional[str]]


def default_tenant_resolver(scope: dict[str, Any]) -> Optional[str]:
    """Tenant informado pelo cliente (header ou subdomínio). NÃO é confiável."""
    headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
    if "x-tenant-id" in headers:
        return headers["x-tenant-id"][:64]
    host = headers.get("host", "").split(":")[0]
    parts = host.split(".")
    return parts[0] if len(parts) > 2 else None


class FailedAuthLogMiddleware:
    def __init__(
        self,
        app,
        *,
        sink: Optional[AuthFailureSink] = None,
        auth_paths: Iterable[str] = ("/auth/login", "/auth/token", "/auth/refresh"),
        max_body_bytes: int = 16 * 1024,
        trust_proxy_headers: bool = False,
        tenant_resolver: TenantResolver = default_tenant_resolver,
    ) -> None:
        self.app = app
        self.sink = sink or LoggingSink()
        self.auth_paths = tuple(auth_paths)
        self.max_body_bytes = max_body_bytes
        self.trust_proxy_headers = trust_proxy_headers
        self.tenant_resolver = tenant_resolver

    # -- helpers ---------------------------------------------------------
    def _is_auth_path(self, path: str) -> bool:
        return any(path.rstrip("/") == p.rstrip("/") for p in self.auth_paths)

    def _is_auth_failure(self, status: int, is_auth_path: bool) -> bool:
        if status == 401:
            return True
        # Em rotas de login, 403 (conta bloqueada) e 429 (rate limit) também importam.
        return is_auth_path and status in (403, 429)

    def _client_ip(self, scope: dict[str, Any]) -> Optional[str]:
        if self.trust_proxy_headers:
            for k, v in scope["headers"]:
                if k == b"x-forwarded-for":
                    return v.decode("latin-1").split(",")[0].strip()[:64]
        client = scope.get("client")
        return client[0] if client else None

    async def _buffer_body(self, scope, receive) -> tuple[Optional[bytes], Callable]:
        """
        Lê o corpo (se pequeno e com Content-Length declarado) e devolve uma
        função `receive` que o reapresenta intacto à aplicação.
        """
        headers = {k: v for k, v in scope["headers"]}
        try:
            declared = int(headers.get(b"content-length", b"-1"))
        except ValueError:
            declared = -1
        if declared < 0 or declared > self.max_body_bytes:
            return None, receive  # grande/chunked: não buffera, não registra corpo

        chunks: list[bytes] = []
        more = True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunks.append(message.get("body", b""))
            more = message.get("more_body", False)
        body = b"".join(chunks)

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        return body, replay

    # -- ASGI ------------------------------------------------------------
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        path = scope["path"]
        is_auth_path = self._is_auth_path(path)

        body: Optional[bytes] = None
        if is_auth_path:
            body, receive = await self._buffer_body(scope, receive)

        status_holder = {"code": 0}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            status = status_holder["code"]
            if self._is_auth_failure(status, is_auth_path):
                await self._record(scope, status, body, is_auth_path, started)

    async def _record(self, scope, status, body, is_auth_path, started) -> None:
        try:
            headers = _sanitize_headers(scope["headers"])
            record: dict[str, Any] = {
                "event": "auth_failure",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": headers.get("x-request-id") or str(uuid.uuid4()),
                "tenant_hint": self.tenant_resolver(scope),  # não confiável
                "method": scope["method"],
                "path": scope["path"][:512],
                "query": _sanitize_query(scope.get("query_string", b"")),
                "client_ip": self._client_ip(scope),
                "status": status,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "headers": headers,
            }
            if is_auth_path:
                if body is None:
                    record["body"] = {"note": "corpo omitido (grande ou sem Content-Length)"}
                else:
                    record["body"] = _sanitize_body(body, headers.get("content-type", ""))
            await self.sink.write(record)
        except Exception:  # o log jamais pode afetar a resposta ao cliente
            _log.exception("falha ao registrar tentativa de autenticação malsucedida")