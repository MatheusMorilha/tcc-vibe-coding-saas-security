"""
auth_failure_log.py

Middleware ASGI que registra tentativas de autenticação malsucedidas, preservando
o que foi enviado na requisição (com redação de segredos) para consulta do suporte.

Decisões de segurança (OWASP Top 10:2021):
  A01 - Cada registro carrega tenant_id; consultas do suporte DEVEM filtrar por ele.
  A02 - Senhas, tokens, cookies e Authorization NUNCA são gravados (redação por chave).
        Também não se grava hash do corpo: hash de corpo com senha é atacável offline.
  A03 - Saída em JSON com ensure_ascii (neutraliza quebras de linha => sem log injection);
        consultas SQL de exemplo usam parâmetros, nunca concatenação.
  A04 - Limites: corpo capturado, nº de campos, profundidade e tamanho de strings.
  A05 - Allowlist de cabeçalhos; nada é gravado "por padrão".
  A07 - Registro suficiente para detectar força bruta / credential stuffing.
  A08 - Cada registro é assinado com HMAC (detecção de adulteração).
  A09 - Log estruturado, falha de gravação é isolada e sinalizada, sem vazar dados.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, Protocol
from urllib.parse import parse_qsl

_log = logging.getLogger(__name__)

# ----------------------------------------------------------------------------
# Sanitização e redação
# ----------------------------------------------------------------------------
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Qualquer chave que contenha um destes trechos tem o valor substituído.
_SENSITIVE_PARTS = (
    "pass", "senha", "secret", "segredo", "token", "otp", "totp", "mfa", "pin",
    "apikey", "api_key", "api-key", "authorization", "cookie", "credential",
    "signature", "assinatura", "cvv", "card", "cartao",
)
REDACTED = "[REDACTED]"
_MAX_DEPTH = 6
_MAX_ITEMS = 50
_MAX_STR = 256


def _is_sensitive(key: Any) -> bool:
    k = str(key).lower()
    return any(part in k for part in _SENSITIVE_PARTS)


def _clean(value: Any, limit: int = _MAX_STR) -> str:
    """Remove caracteres de controle e limita o tamanho (anti log injection / DoS)."""
    s = _CONTROL_CHARS.sub(" ", str(value))
    return s if len(s) <= limit else s[:limit] + "…"


def _redact(obj: Any, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        return "[TRUNCATED]"
    if isinstance(obj, Mapping):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(obj.items()):
            if i >= _MAX_ITEMS:
                out["__truncated__"] = True
                break
            out[_clean(k, 64)] = REDACTED if _is_sensitive(k) else _redact(v, depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        return [_redact(v, depth + 1) for v in obj[:_MAX_ITEMS]]
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    return _clean(obj)


def _pairs_to_dict(pairs: list[tuple[str, str]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            out[k] = (out[k] if isinstance(out[k], list) else [out[k]]) + [v]
        else:
            out[k] = v
    return out


def _parse_query(raw: bytes) -> Any:
    try:
        pairs = parse_qsl(raw.decode("latin-1"), keep_blank_values=True, max_num_fields=_MAX_ITEMS)
    except ValueError:
        return "[QUERY_INVALIDA_OU_EXCESSIVA]"
    return _redact(_pairs_to_dict(pairs))


def _summarize_body(body: bytes, content_type: str, total: int, truncated: bool) -> dict[str, Any]:
    ctype = content_type.split(";")[0].strip().lower()
    summary: dict[str, Any] = {
        "content_type": _clean(ctype, 100),
        "size_bytes": total,
        "truncated": truncated,
        "parsed": None,
    }
    if not body:
        return summary
    if truncated:
        summary["note"] = "corpo excedeu o limite de captura; conteudo nao registrado"
        return summary
    try:
        text = body.decode("utf-8")
        if ctype == "application/json" or ctype.endswith("+json"):
            summary["parsed"] = _redact(json.loads(text))
        elif ctype == "application/x-www-form-urlencoded":
            pairs = parse_qsl(text, keep_blank_values=True, max_num_fields=_MAX_ITEMS)
            summary["parsed"] = _redact(_pairs_to_dict(pairs))
        else:
            # multipart, binário, XML etc.: não há como garantir a redação.
            summary["note"] = "content-type nao registrado"
    except (UnicodeDecodeError, ValueError):
        summary["note"] = "corpo malformado; conteudo nao registrado"
    return summary


# ----------------------------------------------------------------------------
# Configuração
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class FailedAuthLogConfig:
    # Rotas de login/token: nelas, 401 e 403 contam como falha de autenticação.
    login_paths: frozenset[str] = frozenset({"/auth/login", "/api/v1/auth/login", "/api/v1/auth/token"})
    # Em qualquer outra rota, apenas 401 (403 é autorização, não autenticação).
    failure_statuses: frozenset[int] = frozenset({401})
    login_failure_statuses: frozenset[int] = frozenset({401, 403})
    capture_methods: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
    max_body_bytes: int = 16 * 1024
    sink_timeout_s: float = 2.0
    # Cabeçalhos permitidos (allowlist). Authorization/Cookie ficam de fora de propósito.
    allowed_headers: frozenset[str] = frozenset({
        "user-agent", "content-type", "content-length", "origin", "referer",
        "host", "accept-language", "x-request-id",
    })
    # Só confie em X-Forwarded-For se o peer direto for um proxy seu.
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = field(default_factory=tuple)


TenantResolver = Callable[[Mapping[str, Any]], Optional[str]]


def _default_tenant_resolver(scope: Mapping[str, Any]) -> Optional[str]:
    """
    Usa o tenant resolvido pela própria aplicação (ex.: por subdomínio/rota).
    NÃO use cabeçalho enviado pelo cliente (ex.: X-Tenant-Id) como fonte de verdade.
    """
    state = scope.get("state")
    tenant = state.get("tenant_id") if isinstance(state, Mapping) else None
    return str(tenant) if tenant is not None and _SAFE_ID.match(str(tenant)) else None


# ----------------------------------------------------------------------------
# Destino (sink) dos registros
# ----------------------------------------------------------------------------
class AuthFailureSink(Protocol):
    async def write(self, record: dict[str, Any]) -> None: ...


def _canonical(record: Mapping[str, Any]) -> str:
    # ensure_ascii=True escapa \n, \r e unicode => uma linha por registro, sem injeção.
    return json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)


class SignedJsonLoggerSink:
    """
    Escreve JSON em uma linha, assinado com HMAC-SHA256, no logger 'security.auth_failures'.
    Em produção, encaminhe esse logger (via QueueHandler) para armazenamento append-only
    / SIEM, com acesso restrito. A chave deve vir de um cofre de segredos, nunca do código.
    """

    def __init__(self, hmac_key: bytes, logger: Optional[logging.Logger] = None) -> None:
        if len(hmac_key) < 32:
            raise ValueError("hmac_key deve ter ao menos 32 bytes")
        self._key = hmac_key
        self._logger = logger or logging.getLogger("security.auth_failures")

    async def write(self, record: dict[str, Any]) -> None:
        sig = hmac.new(self._key, _canonical(record).encode(), hashlib.sha256).hexdigest()
        self._logger.warning(_canonical({"v": 1, "sig": sig, "record": record}))

    def verify(self, envelope: Mapping[str, Any]) -> bool:
        expected = hmac.new(self._key, _canonical(envelope["record"]).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, str(envelope.get("sig", "")))


# Esquema sugerido caso o sink grave em banco (PostgreSQL). Habilite Row-Level Security
# por tenant_id e restrinja o papel do suporte a SELECT.
SCHEMA_SQL = """
CREATE TABLE auth_failure_log (
    id           UUID PRIMARY KEY,
    occurred_at  TIMESTAMPTZ NOT NULL,
    tenant_id    TEXT,
    request_id   TEXT NOT NULL,
    client_ip    INET,
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,
    status       INTEGER NOT NULL,
    record       JSONB NOT NULL,
    sig          TEXT NOT NULL
);
CREATE INDEX ON auth_failure_log (tenant_id, occurred_at DESC);
"""


def build_support_query(tenant_id: str, since: datetime, limit: int = 100) -> tuple[str, tuple[Any, ...]]:
    """Consulta SEMPRE parametrizada e SEMPRE escopada por tenant (DB-API, estilo %s)."""
    limit = max(1, min(int(limit), 500))
    sql = (
        "SELECT id, occurred_at, request_id, client_ip, method, path, status, record "
        "FROM auth_failure_log WHERE tenant_id = %s AND occurred_at >= %s "
        "ORDER BY occurred_at DESC LIMIT %s"
    )
    return sql, (tenant_id, since, limit)


# ----------------------------------------------------------------------------
# Middleware
# ----------------------------------------------------------------------------
class FailedAuthLogMiddleware:
    def __init__(
        self,
        app: Any,
        sink: AuthFailureSink,
        config: Optional[FailedAuthLogConfig] = None,
        tenant_resolver: TenantResolver = _default_tenant_resolver,
    ) -> None:
        self.app = app
        self.sink = sink
        self.cfg = config or FailedAuthLogConfig()
        self.tenant_resolver = tenant_resolver

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        cfg = self.cfg
        capture = scope["method"].upper() in cfg.capture_methods
        captured = bytearray()
        st: dict[str, Any] = {"total": 0, "truncated": False, "status": None}
        started = time.monotonic()

        async def recv_wrapper() -> dict:
            message = await receive()
            if capture and message["type"] == "http.request":
                chunk = message.get("body", b"")
                st["total"] += len(chunk)
                room = cfg.max_body_bytes - len(captured)
                if room > 0:
                    captured.extend(chunk[:room])
                if len(chunk) > max(room, 0):
                    st["truncated"] = True
            return message  # repassa inalterada

        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start":
                st["status"] = message["status"]
            await send(message)

        await self.app(scope, recv_wrapper, send_wrapper)

        if not self._is_auth_failure(scope.get("path", ""), st["status"]):
            return
        try:
            record = self._build_record(scope, bytes(captured), st, time.monotonic() - started)
            await asyncio.wait_for(self.sink.write(record), timeout=cfg.sink_timeout_s)
        except Exception as exc:  # nunca quebra a resposta; não vaza dados no erro
            _log.error("falha ao gravar log de autenticacao: %s", type(exc).__name__)
        finally:
            captured.clear()

    # -- helpers --------------------------------------------------------------
    def _is_auth_failure(self, path: str, status: Optional[int]) -> bool:
        if status is None:
            return False
        if path.rstrip("/") in self.cfg.login_paths:
            return status in self.cfg.login_failure_statuses
        return status in self.cfg.failure_statuses

    def _client_ip(self, scope: Mapping[str, Any], headers: Mapping[str, str]) -> Optional[str]:
        client = scope.get("client")
        if not client:
            return None
        try:
            peer = ipaddress.ip_address(client[0])
        except ValueError:
            return None
        trusted = self.cfg.trusted_proxies
        if not any(peer in net for net in trusted):
            return str(peer)  # peer não é proxy confiável: ignora X-Forwarded-For
        for part in reversed([p.strip() for p in headers.get("x-forwarded-for", "").split(",")]):
            try:
                addr = ipaddress.ip_address(part)
            except ValueError:
                break
            if not any(addr in net for net in trusted):
                return str(addr)
        return str(peer)

    def _build_record(self, scope: dict, body: bytes, st: dict, elapsed: float) -> dict[str, Any]:
        raw_headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}

        # Não grava o valor de Authorization; apenas o esquema usado.
        auth = raw_headers.get("authorization")
        scheme = None
        if auth:
            first = auth.split(" ", 1)[0].lower()
            scheme = first if first in {"bearer", "basic", "digest"} else "other"

        req_id = raw_headers.get("x-request-id", "")
        req_id = req_id if _SAFE_ID.match(req_id) else uuid.uuid4().hex

        tenant = None
        try:
            tenant = self.tenant_resolver(scope)
        except Exception:
            pass

        return {
            "id": str(uuid.uuid4()),
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "request_id": req_id,
            "tenant_id": tenant,
            "client_ip": self._client_ip(scope, raw_headers),
            "method": _clean(scope.get("method", ""), 10),
            "path": _clean(scope.get("path", ""), 512),
            "query": _parse_query(scope.get("query_string", b"")),
            "status": st["status"],
            "auth_scheme": scheme,
            "headers": {k: _clean(v) for k, v in raw_headers.items() if k in self.cfg.allowed_headers},
            "body": _summarize_body(body, raw_headers.get("content-type", ""), st["total"], st["truncated"]),
            "duration_ms": round(elapsed * 1000, 1),
        }