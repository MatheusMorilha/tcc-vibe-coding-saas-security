"""request_logging.py"""
import json
import logging
import re
import time
import uuid
from typing import Any
from urllib.parse import parse_qsl, urlencode

logger = logging.getLogger("api.request_log")

REDACTED = "[REDACTED]"
MAX_BODY_BYTES = 16 * 1024      # bytes capturados do corpo
MAX_STRING_LEN = 2_000          # tamanho máximo de strings individuais no log
MAX_LIST_ITEMS = 50             # itens máximos de listas no log
MAX_DEPTH = 10

# Fragmentos que, presentes no nome do campo/cabeçalho, indicam dado sensível.
SENSITIVE_FRAGMENTS = (
    "password", "passwd", "senha", "secret", "token", "authorization",
    "api_key", "apikey", "credential", "private_key", "cookie", "otp",
    "cvv", "cvc", "card", "cartao", "cartão", "cpf", "cnpj", "session",
)

# Únicos cabeçalhos registrados com valor (allowlist: mais seguro que denylist).
LOGGED_HEADERS = {
    "content-type", "content-length", "accept", "accept-language",
    "user-agent", "origin", "referer", "x-request-id", "x-forwarded-for",
    "x-forwarded-proto", "host",
}

SKIP_PATHS = {"/health", "/healthz", "/metrics"}

_REQUEST_ID_RE = re.compile(r"^[\w\-]{8,64}$")


def _is_sensitive(key: str) -> bool:
    k = key.lower().replace("-", "_")
    return any(fragment in k for fragment in SENSITIVE_FRAGMENTS)


# Fallback textual (JSON truncado/inválido ou texto livre): mascara "chave": "valor"
_TEXT_PAIR_RE = re.compile(
    r'("?(?P<k>[\w\-\.]+)"?\s*[:=]\s*)(?P<v>"(?:[^"\\]|\\.)*"?|[^\s,&}]+)'
)


def _redact_text(text: str) -> str:
    def repl(m: re.Match) -> str:
        if _is_sensitive(m.group("k")):
            return f'{m.group(1)}"{REDACTED}"'
        return m.group(0)

    return _TEXT_PAIR_RE.sub(repl, text)


def _redact_obj(obj: Any, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        return "[MAX_DEPTH]"
    if isinstance(obj, dict):
        return {
            str(k): (REDACTED if _is_sensitive(str(k)) else _redact_obj(v, depth + 1))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        items = [_redact_obj(i, depth + 1) for i in obj[:MAX_LIST_ITEMS]]
        if len(obj) > MAX_LIST_ITEMS:
            items.append(f"[+{len(obj) - MAX_LIST_ITEMS} itens omitidos]")
        return items
    if isinstance(obj, str) and len(obj) > MAX_STRING_LEN:
        return obj[:MAX_STRING_LEN] + f"...[+{len(obj) - MAX_STRING_LEN} chars]"
    return obj


def _redact_pairs(pairs: list[tuple[str, str]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        val = REDACTED if _is_sensitive(k) else v[:MAX_STRING_LEN]
        if k in out:  # chave repetida -> lista
            out[k] = (out[k] if isinstance(out[k], list) else [out[k]]) + [val]
        else:
            out[k] = val
    return out


def _describe_body(body: bytes, total: int, truncated: bool, content_type: str) -> Any:
    if total == 0:
        return None
    ct = content_type.split(";")[0].strip().lower()

    if ct == "application/json" or ct.endswith("+json"):
        text = body.decode("utf-8", errors="replace")
        if not truncated:
            try:
                return _redact_obj(json.loads(text))
            except ValueError:
                pass
        return _redact_text(text)  # truncado ou JSON inválido

    if ct == "application/x-www-form-urlencoded":
        text = body.decode("utf-8", errors="replace")
        return _redact_pairs(parse_qsl(text, keep_blank_values=True))

    if ct.startswith("text/") or ct in {"application/xml"}:
        return _redact_text(body.decode("utf-8", errors="replace"))

    # multipart, octet-stream, imagens etc.: só metadados
    return f"[omitido: {ct or 'sem content-type'}, {total} bytes]"


def _redact_query(raw_qs: bytes) -> dict[str, Any]:
    return _redact_pairs(parse_qsl(raw_qs.decode("latin-1"), keep_blank_values=True))


class RequestLogMiddleware:
    """Middleware ASGI que registra uma linha JSON por requisição."""

    def __init__(self, app, skip_paths: set[str] | None = None):
        self.app = app
        self.skip_paths = skip_paths if skip_paths is not None else SKIP_PATHS

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] in self.skip_paths:
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}

        incoming_id = headers.get("x-request-id", "")
        request_id = incoming_id if _REQUEST_ID_RE.match(incoming_id) else uuid.uuid4().hex

        # Dicionário compartilhado com request.state (Starlette/FastAPI):
        # a camada de autenticação preenche tenant_id / user_id aqui.
        state = scope.setdefault("state", {})
        state["request_id"] = request_id

        body_buf = bytearray()
        total_bytes = 0
        truncated = False
        status_code = 500  # assume erro se a app lançar exceção antes de responder

        async def receive_wrapper():
            nonlocal total_bytes, truncated
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                total_bytes += len(chunk)
                room = MAX_BODY_BYTES - len(body_buf)
                if room > 0:
                    body_buf.extend(chunk[:room])
                if len(chunk) > max(room, 0):
                    truncated = True
            return message

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                message.setdefault("headers", [])
                message["headers"].append((b"x-request-id", request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        finally:
            self._emit(scope, headers, state, request_id, status_code,
                       bytes(body_buf), total_bytes, truncated, started)

    def _emit(self, scope, headers, state, request_id, status_code,
              body, total_bytes, truncated, started):
        try:
            client = scope.get("client")
            record = {
                "event": "http_request",
                "request_id": request_id,
                "tenant_id": state.get("tenant_id"),
                "user_id": state.get("user_id"),
                "method": scope["method"],
                "path": scope["path"],
                "query": _redact_query(scope.get("query_string", b"")),
                "status": status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "client_ip": client[0] if client else None,
                "headers": {k: v for k, v in headers.items() if k in LOGGED_HEADERS},
                "other_header_names": sorted(k for k in headers if k not in LOGGED_HEADERS),
                "body": _describe_body(body, total_bytes, truncated,
                                       headers.get("content-type", "")),
                "body_bytes": total_bytes,
                "body_truncated": truncated,
            }
            level = logging.ERROR if status_code >= 500 else logging.INFO
            logger.log(level, json.dumps(record, ensure_ascii=False, default=str))
        except Exception:  # log jamais pode quebrar a requisição
            logger.exception("falha ao registrar log da requisição")